const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Broker = @import("../../broker.zig").Broker;
const BlockedWrite = @import("../../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;

test "MQTT fanout recipient transport failure preserves publisher liveness" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        for ([_]mqtt.QoS{ .at_most_once, .at_least_once, .exactly_once }) |qos| {
            for ([_]bool{ false, true }) |persistent| try recipientFailure(protocol, qos, persistent);
        }
    }
}

fn recipientFailure(protocol: mqtt.ProtocolVersion, qos: mqtt.QoS, persistent: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var blocked = BlockedWrite{ .delegate = io, .packet_type = .publish, .failure = error.ConnectionResetByPeer };
    BlockedWrite.active = &blocked;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var broker = try Broker.listen(allocator, observed_io, .{ .ip4 = .loopback(0) }, .{ .limits = .{ .max_connections = 2, .runtime = .{ .max_packet_size = 4096 } }, .accept = .{ .protocol = protocol } });
    defer broker.deinit();
    const Server = struct {
        broker: *Broker,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.broker.serve(2) catch |err| {
                self.err = err;
            };
        }
    };
    var server = Server{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Server.run, .{&server});
    var joined = false;
    defer if (!joined) {
        broker.shutdownActiveConnections();
        thread.join();
    };
    var subscriber = try runtime.Client.connect(allocator, io, broker.address(), .{
        .protocol = protocol,
        .client_id = "fanout-recipient",
        .clean_start = !persistent,
        .properties = if (protocol == .v5 and persistent) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} else &.{},
    });
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "fanout/failure", .qos = .at_most_once }}, .{});
    suback.deinit(allocator);
    var publisher = try runtime.Client.connect(allocator, io, broker.address(), .{ .protocol = protocol, .client_id = "fanout-source" });
    defer publisher.close();
    blocked.armed.store(true, .release);
    try publisher.publish("fanout/failure", "independent source", .{ .qos = qos });
    try publisher.pingWithTimeout(.fromSeconds(1));
    try std.testing.expect(blocked.entered.load(.acquire));
    try publisher.disconnect(0);
    subscriber.shutdown() catch {};
    thread.join();
    joined = true;
    if (server.err) |err| return err;
}

test "MQTT fanout continues healthy recipients after one failed target" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var blocked = BlockedWrite{ .delegate = io, .packet_type = .publish, .failure = error.ConnectionResetByPeer, .once = true };
    BlockedWrite.active = &blocked;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var broker = try Broker.listen(allocator, observed_io, .{ .ip4 = .loopback(0) }, .{ .limits = .{ .max_connections = 3, .runtime = .{ .max_packet_size = 4096 } } });
    defer broker.deinit();
    const Server = struct {
        broker: *Broker,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.broker.serve(3) catch |err| {
                self.err = err;
            };
        }
    };
    var server = Server{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Server.run, .{&server});
    var joined = false;
    defer if (!joined) {
        broker.shutdownActiveConnections();
        thread.join();
    };
    var first = try runtime.Client.connect(allocator, io, broker.address(), .{ .protocol = .v5, .client_id = "fanout-first" });
    defer first.close();
    var second = try runtime.Client.connect(allocator, io, broker.address(), .{ .protocol = .v5, .client_id = "fanout-second" });
    defer second.close();
    for ([_]*runtime.Connection{ &first, &second }) |subscriber| {
        var ack = try subscriber.subscribe(&.{.{ .topic_filter = "fanout/mixed", .qos = .at_most_once }}, .{});
        ack.deinit(allocator);
    }
    var publisher = try runtime.Client.connect(allocator, io, broker.address(), .{ .protocol = .v5, .client_id = "fanout-mixed-source" });
    defer publisher.close();
    blocked.armed.store(true, .release);
    try publisher.publish("fanout/mixed", "surviving delivery", .{ .qos = .exactly_once });
    try publisher.pingWithTimeout(.fromSeconds(1));
    var deliveries: usize = 0;
    var closed: usize = 0;
    for ([_]*runtime.Connection{ &first, &second }) |subscriber| {
        var event = subscriber.readClientPacketEventWithTimeout(.fromSeconds(1)) catch |err| switch (err) {
            error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {
                closed += 1;
                continue;
            },
            else => return err,
        };
        defer event.deinit(allocator);
        try std.testing.expect(event == .publish);
        try std.testing.expectEqualStrings("surviving delivery", event.publish.publish.payload);
        deliveries += 1;
        try subscriber.disconnect(0);
    }
    try std.testing.expectEqual(@as(usize, 1), closed);
    try std.testing.expectEqual(@as(usize, 1), deliveries);
    try publisher.disconnect(0);
    thread.join();
    joined = true;
    if (server.err) |err| return err;
}
