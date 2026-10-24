const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const broker_mod = @import("../broker.zig");

test "MQTT reauthentication live broker preserves identity subscriptions and QoS progress" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const Policy = struct {
        auth_calls: usize = 0,
        publishes: usize = 0,
        subscriptions: usize = 0,
        identity_valid: bool = true,
        fn start(_: *anyopaque, pending: *runtime.PendingAcceptedClient) broker_mod.Error!void {
            try pending.setAuthenticatedUsername("authenticated");
            try pending.authorizeAuthentication();
        }
        fn auth(context: *anyopaque, connection: *runtime.Connection, packet: mqtt.Auth, complete: bool) broker_mod.Error!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (complete) return error.InvalidAuthenticationState;
            self.auth_calls += 1;
            switch (packet.reason_code) {
                0x19 => try connection.continueReauthentication(0x18, "challenge"),
                0x18 => try connection.continueReauthentication(0, "success"),
                else => return error.InvalidAuthenticationState,
            }
        }
        fn publish(context: *anyopaque, connect: mqtt.Connect, _: mqtt.Publish) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.publishes += 1;
            const valid = std.mem.eql(u8, connect.username orelse "", "authenticated");
            self.identity_valid = self.identity_valid and valid;
            return valid;
        }
        fn subscribe(context: *anyopaque, connect: mqtt.Connect, _: mqtt.Subscription) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.subscriptions += 1;
            const valid = std.mem.eql(u8, connect.username orelse "", "authenticated");
            self.identity_valid = self.identity_valid and valid;
            return valid;
        }
    };
    var policy: Policy = .{};
    var broker = try broker_mod.Broker.listen(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{
        .limits = .{ .max_connections = 1, .runtime = .{ .max_packet_size = 4096 } },
        .authentication = .{ .context = &policy, .start = Policy.start, .handle = Policy.auth },
        .access_control = .{ .context = &policy, .authorize_publish = Policy.publish, .authorize_subscribe = Policy.subscribe },
    });
    defer broker.deinit();
    const Worker = struct {
        broker: *broker_mod.Broker,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.broker.serve(1) catch |err| {
                self.err = err;
            };
        }
    };
    var worker = Worker{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const Handler = struct {
        fn respond(_: *anyopaque, _: mqtt.Auth) runtime.Error![]const mqtt.Property {
            return error.InvalidAuthenticationState;
        }
    };
    var dummy: u8 = 0;
    var connection = try runtime.Client.connect(std.testing.allocator, threaded.io(), broker.address(), .{
        .client_id = "reauth-live",
        .username = "wire-identity",
        .properties = &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }},
        .authentication = .{ .context = &dummy, .respond = Handler.respond },
        .max_outgoing_inflight = 1,
        .receive_maximum = 1,
    });
    defer connection.close();
    try connection.beginReauthentication("refresh");
    var subscription = try connection.subscribeWithTimeout(&.{.{ .topic_filter = "auth/live", .qos = .at_least_once }}, .{}, .fromSeconds(2));
    defer subscription.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{1}, subscription.suback.reason_codes);
    var challenge = try connection.receiveReauthenticationWithTimeout(.fromSeconds(2));
    defer challenge.auth.deinit(std.testing.allocator);
    try std.testing.expect(!challenge.complete);
    inline for (.{ mqtt.QoS.at_least_once, mqtt.QoS.exactly_once }) |qos| {
        var progress: runtime.PublishProgress = .{};
        try connection.publishWithTimeout("auth/live", "payload", .{ .qos = qos }, &progress, .fromSeconds(2));
        try std.testing.expect(progress.completed);
        try std.testing.expectEqual(@as(u16, 0), connection.outgoing_inflight);
        try std.testing.expectEqual(@import("../runtime/auth.zig").Phase.reauthenticating, connection.authentication.phase);
        var delivery = try connection.readPublish();
        defer delivery.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("payload", delivery.publish.payload);
        try std.testing.expectEqual(mqtt.QoS.at_least_once, delivery.publish.qos);
        try connection.writePubAck(delivery.publish.packet_id.?, 0);
        try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    }
    try connection.pingWithTimeout(.fromSeconds(2));
    try connection.continueReauthentication(0x18, "reply");
    var result = try connection.receiveReauthenticationWithTimeout(.fromSeconds(2));
    defer result.auth.deinit(std.testing.allocator);
    try std.testing.expect(result.complete);
    try connection.pingWithTimeout(.fromSeconds(2));
    try connection.disconnect(0);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), policy.auth_calls);
    try std.testing.expectEqual(@as(usize, 2), policy.publishes);
    try std.testing.expectEqual(@as(usize, 1), policy.subscriptions);
    try std.testing.expect(policy.identity_valid);
}
