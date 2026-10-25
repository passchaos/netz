//! A failed local reset cannot turn a known-lost broker Session into recovery.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

test "MQTT reconnect retries a failed Session reset before replaying any old QoS" {
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
                var first = try self.server.acceptWithTimeout(.{ .protocol = .v5 }, .fromSeconds(3));
                defer first.deinit(self.server.allocator);
                first.connection.readPingReq() catch |err| switch (err) {
                    error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
                    else => return err,
                };
            }
            var retry = try self.server.acceptWithTimeout(.{ .protocol = .v5, .session_present = true }, .fromSeconds(3));
            defer retry.deinit(self.server.allocator);
            var event = try retry.connection.readBrokerEventWithTimeout(.fromSeconds(2));
            defer event.deinit(self.server.allocator);
            try std.testing.expect(event == .pingreq);
            try retry.connection.writePingResp();
            var disconnect = try retry.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const Connector = struct {
        address: std.Io.net.IpAddress,
        failing: *std.testing.FailingAllocator,
        fail_reset: bool = true,

        fn attempt(context: *anyopaque, alloc: std.mem.Allocator, attempt_io: std.Io, options: runtime.ConnectOptions) runtime.Error!runtime.ConnectAttempt {
            return attemptUntil(context, alloc, attempt_io, options, .fromNow(attempt_io, .{ .raw = .fromSeconds(2), .clock = .awake }));
        }

        fn attemptUntil(context: *anyopaque, alloc: std.mem.Allocator, attempt_io: std.Io, options: runtime.ConnectOptions, deadline: std.Io.Clock.Timestamp) runtime.Error!runtime.ConnectAttempt {
            const self: *@This() = @ptrCast(@alignCast(context));
            const result = try runtime.Client.connectAttemptWithDeadline(alloc, attempt_io, self.address, options, deadline);
            if (self.fail_reset) self.failing.fail_index = self.failing.alloc_index;
            return result;
        }
    };
    var connector = Connector{ .address = server.address(), .failing = &failing };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(failing.allocator(), io, .{ .context = &connector, .connect_attempt = Connector.attempt, .connect_attempt_deadline = Connector.attemptUntil }, .{
        .protocol = .v5,
        .client_id = "reset-identity",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    }, .{}, &shutdown);
    defer client.deinit();
    const old = try client.outgoing.beginImmediatePublish(client.outgoing_handle, "old/pending", "obsolete", .{ .qos = .exactly_once, .now = .zero }, 8);
    try std.testing.expectError(error.OutOfMemory, client.connectWithTimeout(.fromSeconds(2)));
    try std.testing.expect(client.connection() == null);
    try std.testing.expect((try client.outgoingQoSState(old.packet_id)) != null);
    try std.testing.expectEqualStrings("reset-identity", client.clientId());
    var image: std.ArrayList(u8) = .empty;
    defer image.deinit(allocator);
    try image.appendSlice(allocator, "outer");
    try std.testing.expectError(error.SessionLost, client.writeSessionSnapshotAt(&image, .zero, .zero));
    try std.testing.expectEqualStrings("outer", image.items);
    connector.fail_reset = false;
    failing.fail_index = std.math.maxInt(usize);
    const connected = try client.connectWithTimeout(.fromSeconds(2));
    try std.testing.expect(connected.session_present and !connected.session_resumed);
    try std.testing.expect(!client.sessionResumed());
    try std.testing.expectEqual(@as(usize, 0), (try client.outgoingStats()).inflight_count);
    try client.connection().?.pingWithTimeout(.fromSeconds(2));
    try client.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
