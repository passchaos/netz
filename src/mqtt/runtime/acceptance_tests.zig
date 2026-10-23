const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");

test "MQTT prepared acceptance owns properties and commits negotiation only on send" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var server = try runtime.Server.listen(failing.allocator(), io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();
    const Client = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        result: ?runtime.ConnectResult = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.result = runtime.Client.connectWithConnAckWithTimeout(std.testing.allocator, self.io, self.address, .{
                .protocol = .v5,
                .client_id = "prepared-acceptance",
                .properties = &.{
                    .{ .byte = .{ .id = .request_response_information, .value = 1 } },
                    .{ .two_byte = .{ .id = .topic_alias_maximum, .value = 64 } },
                },
            }, .fromSeconds(5)) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var client = Client{ .io = io, .address = server.address() };
    const thread = try std.Thread.spawn(.{}, Client.run, .{&client});
    var joined = false;
    defer if (!joined) {
        thread.join();
        if (client.result) |*result| result.deinit(allocator);
    };
    var pending = try server.acceptPendingWithTimeout(.{}, .fromSeconds(5));
    var pending_owned = true;
    defer if (pending_owned) pending.deinit(failing.allocator());
    const incoming_limit = pending.connection.max_incoming_inflight;
    const keep_alive = pending.connection.keep_alive_seconds;
    const aliases = pending.connection.peer_topic_alias_maximum;
    const traffic = pending.connection.trafficStats();
    var information = "reply-prefix".*;
    const options = runtime.AcceptOptions{
        .response_information = &information,
        .max_outgoing_inflight = 64,
        .max_outgoing_topic_aliases = 4,
        .topic_alias_maximum = 8,
        .server_keep_alive_seconds = 5,
        .maximum_qos = .at_least_once,
        .retain_available = false,
    };
    var measured = try pending.prepareFinish(options);
    const packet_len = measured.connack.bytes().len;
    measured.deinit();
    pending.connection.peer_max_packet_size = packet_len - 1;
    try std.testing.expectError(error.OutgoingPacketTooLarge, pending.prepareFinish(options));
    pending.connection.peer_max_packet_size = packet_len;
    var prepared = try pending.prepareFinish(options);
    defer prepared.deinit();
    try std.testing.expectEqual(incoming_limit, pending.connection.max_incoming_inflight);
    try std.testing.expectEqual(keep_alive, pending.connection.keep_alive_seconds);
    try std.testing.expectEqual(aliases, pending.connection.peer_topic_alias_maximum);
    try std.testing.expectEqualDeep(traffic, pending.connection.trafficStats());
    try std.testing.expectEqual(mqtt.QoS.exactly_once, pending.connection.capabilities.local_maximum_qos);
    try std.testing.expect(pending.connection.capabilities.local_retain_available);
    @memset(&information, 'x');
    failing.fail_index = failing.alloc_index;
    var accepted = try pending.finishPrepared(&prepared);
    pending_owned = false;
    defer accepted.deinit(failing.allocator());
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(u16, 64), accepted.connection.max_incoming_inflight);
    try std.testing.expectEqual(@as(u16, 5), accepted.connection.keep_alive_seconds);
    try std.testing.expectEqual(@as(u16, 4), accepted.connection.peer_topic_alias_maximum);
    try std.testing.expectEqual(@as(u16, 8), accepted.connection.incoming_topic_alias_maximum);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, accepted.connection.capabilities.local_maximum_qos);
    try std.testing.expect(!accepted.connection.capabilities.local_retain_available);
    thread.join();
    joined = true;
    if (client.err) |err| return err;
    var result = client.result.?;
    defer result.deinit(allocator);
    try std.testing.expectEqual(packet_len, result.connack.packet.bytes.len);
    try std.testing.expectEqualStrings("reply-prefix", mqtt.responseInformation(result.connack.connack.properties).?);
    try std.testing.expectEqual(@as(u16, 5), result.connection.keep_alive_seconds);
}
