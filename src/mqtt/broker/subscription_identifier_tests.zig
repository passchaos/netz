//! MQTT-3.3.4-4: one Identifier occurrence for every matching subscription.
const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const context = @import("../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;
const support = @import("registration_persistence/test_support.zig");
const allocator = std.testing.allocator;
const topic = "identifiers/value";
const expiry = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }};

fn subscribeOverlaps(connection: *runtime.Connection) !void {
    var ack = try connection.subscribe(&.{
        .{ .topic_filter = "identifiers/#", .qos = .at_least_once },
        .{ .topic_filter = "identifiers/+", .qos = .at_least_once },
        .{ .topic_filter = topic, .qos = .at_least_once },
    }, .{ .properties = &.{.{ .varint = .{ .id = .subscription_identifier, .value = 7 } }} });
    defer ack.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 1 }, ack.suback.reason_codes);
}

fn expectIdentifiers(properties: []const mqtt.Property) !void {
    var count: usize = 0;
    for (properties) |property| {
        if (property == .varint and property.varint.id == .subscription_identifier) {
            try std.testing.expectEqual(@as(usize, 7), property.varint.value);
            count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

fn expectNoFurtherDelivery(connection: *runtime.Connection) !void {
    try connection.pingWithTimeout(.fromSeconds(5));
    var extra = connection.readClientPacketEventWithTimeout(.fromMilliseconds(10)) catch |err| {
        try std.testing.expect(err == error.Timeout);
        return;
    };
    defer extra.deinit(allocator);
    return error.UnexpectedDuplicateDelivery;
}

test "broker MQTT5 coalesced live delivery preserves equal Subscription Identifiers" {
    for ([_]bool{ false, true }) |persistent| {
        for ([_]mqtt.QoS{ .at_most_once, .at_least_once }) |qos| try liveIdentifiers(persistent, qos);
    }
}

fn liveIdentifiers(persistent: bool, qos: mqtt.QoS) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = support.AdmissionOverlap{ .delegate = io };
    support.AdmissionOverlap.active = &observer;
    defer support.AdmissionOverlap.active = null;
    var table = io.vtable.*;
    table.netClose = support.AdmissionOverlap.netClose;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &table };
    var broker = try context.testBrokerFn(allocator, observed_io, 2, 64);
    defer broker.deinit();
    var service = support.OverlapService{ .broker = &broker };
    const server_thread = try std.Thread.spawn(.{}, support.OverlapService.run, .{&service});
    var joined = false;
    defer if (!joined) {
        service.shutdown.set(io);
        server_thread.join();
    };
    var subscriber = try runtime.Client.connectWithTimeout(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "identifier-live-subscriber",
        .clean_start = !persistent,
        .properties = if (persistent) &expiry else &.{},
    }, .fromSeconds(5));
    defer subscriber.close();
    try subscribeOverlaps(&subscriber);
    var publisher = try runtime.Client.connectWithTimeout(allocator, io, broker.address(), .{ .protocol = .v5, .client_id = "identifier-live-publisher" }, .fromSeconds(5));
    defer publisher.close();
    try publisher.publish(topic, "live", .{ .qos = qos });
    var event = try subscriber.readClientPacketEventWithTimeout(.fromSeconds(5));
    defer event.deinit(allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqualStrings(topic, event.publish.publish.topic);
    try std.testing.expectEqualStrings("live", event.publish.publish.payload);
    try std.testing.expectEqual(qos, event.publish.publish.qos);
    try expectIdentifiers(event.publish.publish.properties);
    if (qos == .at_least_once) try subscriber.writePubAck(event.publish.publish.packet_id.?, 0);
    try expectNoFurtherDelivery(&subscriber);
    try support.writeOverlapDisconnect(&subscriber);
    try support.waitOverlap(&observer.first_retired, io);
    try support.expectOverlapEof(&subscriber);
    try support.writeOverlapDisconnect(&publisher);
    try support.waitOverlap(&observer.second_retired, io);
    try support.expectOverlapEof(&publisher);
    service.shutdown.set(io);
    server_thread.join();
    joined = true;
    if (service.err) |err| return err;
}

test "broker MQTT5 offline journal and DUP replay retain equal Subscription Identifiers" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var delivery_id: ?u16 = null;
    for (0..3) |generation| {
        var observer = support.AdmissionOverlap{ .delegate = io };
        support.AdmissionOverlap.active = &observer;
        defer support.AdmissionOverlap.active = null;
        var table = io.vtable.*;
        table.netClose = support.AdmissionOverlap.netClose;
        const observed_io = std.Io{ .userdata = io.userdata, .vtable = &table };
        var broker = try context.testBrokerFn(allocator, observed_io, 2, 64);
        defer broker.deinit();
        if (generation == 0) {
            try broker.createCommitLog(tmp.dir, "identifiers.log", .{});
        } else {
            try broker.restoreCommitLog(tmp.dir, "identifiers.log", .{});
        }
        var service = support.OverlapService{ .broker = &broker };
        const server_thread = try std.Thread.spawn(.{}, support.OverlapService.run, .{&service});
        var joined = false;
        defer if (!joined) {
            service.shutdown.set(io);
            server_thread.join();
        };
        var subscriber = try runtime.Client.connectWithConnAckWithTimeout(allocator, io, broker.address(), .{
            .protocol = .v5,
            .client_id = "identifier-offline-subscriber",
            .clean_start = false,
            .properties = &expiry,
        }, .fromSeconds(5));
        defer subscriber.deinit(allocator);
        try std.testing.expectEqual(generation != 0, subscriber.connack.connack.session_present);
        if (generation == 0) {
            try subscribeOverlaps(&subscriber.connection);
            try support.writeOverlapDisconnect(&subscriber.connection);
            try support.waitOverlap(&observer.first_retired, io);
            try support.expectOverlapEof(&subscriber.connection);
            var publisher = try runtime.Client.connectWithTimeout(allocator, io, broker.address(), .{ .protocol = .v5, .client_id = "identifier-offline-publisher" }, .fromSeconds(5));
            defer publisher.close();
            try publisher.publish(topic, "queued", .{ .qos = .at_least_once });
            try support.writeOverlapDisconnect(&publisher);
            try support.waitOverlap(&observer.second_retired, io);
            try support.expectOverlapEof(&publisher);
        } else {
            var event = try subscriber.connection.readClientPacketEventWithTimeout(.fromSeconds(5));
            defer event.deinit(allocator);
            try std.testing.expect(event == .publish);
            try std.testing.expectEqualStrings(topic, event.publish.publish.topic);
            try std.testing.expectEqualStrings("queued", event.publish.publish.payload);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, event.publish.publish.qos);
            try expectIdentifiers(event.publish.publish.properties);
            if (generation == 1) {
                try std.testing.expect(!event.publish.publish.dup);
                delivery_id = event.publish.publish.packet_id.?;
            } else {
                try std.testing.expect(event.publish.publish.dup);
                try std.testing.expectEqual(delivery_id.?, event.publish.publish.packet_id.?);
                try subscriber.connection.writePubAck(delivery_id.?, 0);
                try expectNoFurtherDelivery(&subscriber.connection);
            }
            try support.writeOverlapDisconnect(&subscriber.connection);
            try support.waitOverlap(&observer.first_retired, io);
            try support.expectOverlapEof(&subscriber.connection);
        }
        service.shutdown.set(io);
        server_thread.join();
        joined = true;
        if (service.err) |err| return err;
    }
    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "identifiers.log", .{});
    const handle = restored.sessions.find("identifier-offline-subscriber", std.Io.Clock.awake.now(io)) orelse return error.SessionNotFound;
    const stats = try restored.sessions.stats(handle);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_count);
    try std.testing.expectEqual(@as(usize, 0), stats.inflight_count);
}
