//! A lost target Session requires a new QoS 1 delivery before source ACK.
const std = @import("std");
const runtime = @import("../runtime.zig");
const broker_mod = @import("../broker.zig");
const outbound = @import("outbound.zig");

test "outbound bridge republishes QoS1 after local target expiry despite Session Present" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
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
                try std.testing.expectEqualStrings("source/value", event.publish.publish.topic);
                try std.testing.expect(!event.publish.publish.dup);
                // Closing before PUBACK loses the zero-expiry target Session.
                try first.connection.shutdown();
            }
            var preserved = try self.server.acceptWithTimeout(.{ .session_present = true }, .fromSeconds(2));
            defer preserved.deinit(self.server.allocator);
            var event = try preserved.connection.readBrokerEventWithTimeout(.fromSeconds(2));
            defer event.deinit(self.server.allocator);
            // The raw CONNACK bit must not cause the source to be completed
            // merely because expiry emptied the target's inflight Store.
            try std.testing.expect(event == .publish);
            try std.testing.expectEqualStrings("source/value", event.publish.publish.topic);
            try std.testing.expectEqualStrings("forward", event.publish.publish.payload);
            try std.testing.expectEqual(.at_least_once, event.publish.publish.qos);
            try std.testing.expect(!event.publish.publish.dup);
            try preserved.connection.writePubAck(event.publish.publish.packet_id.?, 0);
            var disconnect = try preserved.connection.readBrokerEventWithTimeout(.fromSeconds(2));
            defer disconnect.deinit(self.server.allocator);
            try std.testing.expect(disconnect == .disconnect);
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{
        .broker = &local,
        .id = [_]u8{0x60} ** 16,
    }, .{ .address = server.address() }, .{
        .source_connect = .{
            .client_id = "qos1-resume-local",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
        },
        .target_connect = .{
            .client_id = "qos1-resume-target",
            .clean_start = false,
            .connect_timeout = .fromSeconds(2),
            .network_connect_timeout = .fromSeconds(2),
        },
        .target_reconnect_policy = .{ .max_attempts = 1 },
        .rules = &.{.{ .filter = "source/#", .qos = .at_least_once }},
    }, &shutdown);
    defer bridge.deinit();
    _ = try bridge.connect();
    try local.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "source/value",
        .packet_id = null,
        .payload = "forward",
    });
    try std.testing.expectEqual(@as(usize, 1), try bridge.source.pendingCount());
    try std.testing.expect(try bridge.step(.{ .timeout = .fromSeconds(2) }));
    try std.testing.expect(bridge.target_session_present and !bridge.target.sessionResumed());
    try std.testing.expectEqual(@as(u64, 2), bridge.target_session_epoch);
    try std.testing.expectEqual(@as(usize, 0), try bridge.source.pendingCount());
    try bridge.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
