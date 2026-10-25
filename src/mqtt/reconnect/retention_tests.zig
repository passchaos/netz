//! Peer Session expiry must follow the reconnect owner across snapshots.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

test "MQTT reconnect DISCONNECT zero expiry cannot resurrect QoS from a snapshot" {
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
            var accepted = try self.server.acceptWithTimeout(.{ .protocol = .v5 }, .fromSeconds(2));
            defer accepted.deinit(self.server.allocator);
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try accepted.connection.writeSubAck(subscribe.subscribe.packet_id, &.{0}, &.{});
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(?u32, 0), mqtt.sessionExpiryInterval(disconnect.disconnect.properties));
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    const options = runtime.ConnectOptions{ .protocol = .v5, .client_id = "retention", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} };
    var client = try reconnect.Client.init(allocator, io, server.address(), options, .{}, &shutdown);
    defer client.deinit();
    try client.seedSubscription(.{ .topic_filter = "desired/#" }, &.{});
    _ = try client.connectWithTimeout(.fromSeconds(2));
    _ = try client.stagePublish("pending", "payload", .{ .qos = .exactly_once });
    try client.disconnectWithProperties(0, &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 0 } }});
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try client.writeSessionSnapshotAt(&bytes, .zero, .zero);
    var restored = try reconnect.Client.init(allocator, io, server.address(), options, .{}, &shutdown);
    defer restored.deinit();
    try restored.restoreSessionSnapshotAt(bytes.items, .zero, .zero);
    try std.testing.expectEqual(@as(usize, 0), (try restored.outgoingStats()).inflight_count);
    try std.testing.expect(restored.hasSubscription("desired/#"));
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
