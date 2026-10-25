//! CONNACK waiting cannot continue an offline expiry after CONNECT resumes it.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

test "MQTT retention does not expire an accepted reconnect while waiting for CONNACK" {
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
            var pending = try self.server.acceptPendingWithTimeout(.{ .protocol = .v5 }, .fromSeconds(2));
            defer pending.deinit(self.server.allocator);
            try pending.connection.writeConnAck(.{ .session_present = true });
            var event = try pending.connection.readBrokerEventWithTimeout(.fromSeconds(2));
            defer event.deinit(self.server.allocator);
            try std.testing.expect(event == .publish);
            try std.testing.expectEqualStrings("retention/pending", event.publish.publish.topic);
            try pending.connection.writePubAck(event.publish.publish.packet_id.?, 0);
            var disconnect = try pending.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    const Connector = struct {
        address: std.Io.net.IpAddress,
        client: ?*reconnect.Client = null,

        fn attempt(context: *anyopaque, alloc: std.mem.Allocator, attempt_io: std.Io, options: runtime.ConnectOptions) runtime.Error!runtime.ConnectAttempt {
            return attemptUntil(context, alloc, attempt_io, options, .fromNow(attempt_io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
        }

        fn attemptUntil(context: *anyopaque, alloc: std.mem.Allocator, attempt_io: std.Io, options: runtime.ConnectOptions, deadline: std.Io.Clock.Timestamp) runtime.Error!runtime.ConnectAttempt {
            const self: *@This() = @ptrCast(@alignCast(context));
            const result = try runtime.Client.connectAttemptWithDeadline(alloc, attempt_io, self.address, options, deadline);
            // Simulate expiry during the accepted handshake on the owner
            // thread, after the broker has already resumed the Session.
            self.client.?.retention.expires_at = .zero;
            return result;
        }
    };
    var connector = Connector{ .address = server.address() };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(allocator, io, .{ .context = &connector, .connect_attempt = Connector.attempt, .connect_attempt_deadline = Connector.attemptUntil }, .{
        .protocol = .v5,
        .client_id = "slow-connack-retention",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    }, .{}, &shutdown);
    defer client.deinit();
    connector.client = &client;
    const old = try client.outgoing.beginImmediatePublish(client.outgoing_handle, "retention/pending", "live", .{ .qos = .at_least_once, .now = .zero }, 8);
    client.disconnectTransport();
    client.retention.disconnected(std.Io.Clock.awake.now(io));
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    try std.testing.expect((try client.connectWithTimeout(.fromSeconds(2))).session_present);
    try std.testing.expectEqual(old.packet_id, try client.completeNextPublish());
    try client.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
