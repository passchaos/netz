const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");

test "MQTT reauthentication preserves interleaved AUTH publication and PING traffic" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var listener = try runtime.Server.listen(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer listener.deinit();
    const Worker = struct {
        listener: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.exchange() catch |err| {
                self.err = err;
            };
        }
        fn exchange(self: *@This()) !void {
            var pending = try self.listener.acceptPending(.{ .protocol = .v5 });
            var owned = true;
            defer if (owned) pending.deinit(std.testing.allocator);
            try pending.authorizeAuthentication();
            var accepted = try pending.finish(.{ .protocol = .v5 });
            owned = false;
            defer accepted.deinit(std.testing.allocator);
            const connection = &accepted.connection;
            var reauth = try connection.acceptReauthentication();
            defer reauth.deinit(std.testing.allocator);
            try connection.continueReauthentication(0x18, "challenge");
            // These messages share the established identity and QoS limits.
            _ = try connection.writePublish("auth/interleaved", "before-success", .{});
            try connection.readPingReq();
            try connection.writePingResp();
            var reply = try connection.receiveReauthentication();
            defer reply.auth.deinit(std.testing.allocator);
            try std.testing.expect(!reply.complete);
            try std.testing.expectEqualStrings("reply", mqtt.authenticationData(reply.auth.auth.properties).?);
            var publish = try connection.readPublish();
            defer publish.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("from-client", publish.publish.payload);
            try connection.continueReauthentication(0, "done");
            try connection.readPingReq();
            try connection.writePingResp();
        }
    };
    var worker = Worker{ .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const Handler = struct {
        fn respond(_: *anyopaque, _: mqtt.Auth) runtime.Error![]const mqtt.Property {
            return error.InvalidAuthenticationState;
        }
    };
    var dummy: u8 = 0;
    var connection = try runtime.Client.connect(std.testing.allocator, threaded.io(), listener.address(), .{
        .client_id = "reauth-traffic",
        .properties = &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }},
        .authentication = .{ .context = &dummy, .respond = Handler.respond },
    });
    defer connection.close();
    try connection.beginReauthentication("start");
    try connection.pingWithTimeout(.fromSeconds(1));
    var challenge = try connection.receiveReauthentication();
    defer challenge.auth.deinit(std.testing.allocator);
    try std.testing.expect(!challenge.complete);
    var publish = try connection.readPublish();
    defer publish.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("before-success", publish.publish.payload);
    try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    _ = try connection.writePublish("auth/interleaved", "from-client", .{});
    try connection.continueReauthentication(0x18, "reply");
    var complete = try connection.receiveReauthentication();
    defer complete.auth.deinit(std.testing.allocator);
    try std.testing.expect(complete.complete);
    try connection.pingWithTimeout(.fromSeconds(1));
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}
