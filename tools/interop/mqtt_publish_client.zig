const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;
const Mode = enum { ordinary, timeout, deadline };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    var backend = try netz.runtime.Backend.init(init.gpa);
    defer backend.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        var client = try mqtt.runtime.Client.connectWithTimeout(
            init.gpa,
            backend.io(),
            .{ .ip4 = .loopback(port) },
            .{ .protocol = protocol, .client_id = "netz-sync-publish", .max_outgoing_inflight = 4 },
            .fromSeconds(3),
        );
        defer client.close();
        var suback = try client.subscribeWithTimeout(&.{.{ .topic_filter = "completion/self", .qos = .at_most_once }}, .{}, .fromSeconds(3));
        defer suback.deinit(init.gpa);
        try std.testing.expectEqualSlices(u8, &.{0}, suback.suback.reason_codes);

        for (std.enums.values(Mode)) |mode| {
            try exerciseSubscriptions(&client, mode);
            for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| {
                const first = (try write(&client, mode, "first", qos)).?;
                const second = (try write(&client, mode, "second", qos)).?;
                // Mosquitto sends initial acknowledgements in order. Deliberately
                // complete the second first to exercise preservation and later
                // extraction of the first ACK alongside self-delivered messages.
                try complete(&client, mode, second, qos);
                try complete(&client, mode, first, qos);
                try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
                const expected = if (qos == .exactly_once)
                    [_][]const u8{ "second", "first" }
                else
                    [_][]const u8{ "first", "second" };
                for (expected) |payload| try expectDelivery(&client, payload);

                // The ordinary synchronous convenience method has the same
                // interleaved receive contract as split publish completion.
                var progress: mqtt.runtime.PublishProgress = .{};
                switch (mode) {
                    .ordinary => try client.publish("completion/self", "ordinary", .{ .qos = qos }),
                    .timeout => try client.publishWithTimeout("completion/self", "ordinary", .{ .qos = qos }, &progress, .fromSeconds(3)),
                    .deadline => try client.publishWithDeadline("completion/self", "ordinary", .{ .qos = qos }, &progress, client.transport.deadlineFromNow(.fromSeconds(3))),
                }
                if (mode != .ordinary) {
                    try std.testing.expect(progress.publish_sent and progress.completed);
                    try std.testing.expect(progress.packet_id != null);
                }
                try expectDelivery(&client, "ordinary");
            }
        }
        try client.pingWithTimeout(.fromSeconds(3));
        try client.disconnect(0);
    }
    try exerciseDurableSubscriptions(init.gpa, backend.io(), port);
    std.debug.print("netz synchronous publish interop passed: protocols=mqtt31,mqtt311,mqtt5 qos=1,2 reverse-completion=true self-delivery=true wire-order=true split-subscriptions=true reverse-control-completion=true budgets=ordinary,timeout,deadline client_io=zio-std-io server_io=mosquitto\n", .{});
}

fn exerciseDurableSubscriptions(allocator: std.mem.Allocator, io: std.Io, port: u16) !void {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        const properties: []const mqtt.Property = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} else &.{};
        var shutdown: std.Io.Event = .unset;
        var client = try mqtt.reconnect.Client.init(allocator, io, .{ .ip4 = .loopback(port) }, .{ .protocol = protocol, .client_id = "netz-durable-identifier-interop", .clean_start = false, .properties = properties }, .{}, &shutdown);
        defer client.deinit();
        _ = try client.connectWithTimeout(.fromSeconds(3));
        const staged = try client.stagePublish("completion/durable", "staged", .{ .qos = .at_least_once });
        const active = client.connection().?;
        var suback = try client.subscribeWithTimeout(&.{.{ .topic_filter = "completion/unused" }}, .{}, .fromSeconds(3));
        defer suback.deinit(allocator);
        try std.testing.expect(suback.suback.packet_id != staged);
        const unsubscription = try active.writeUnsubscribe(&.{"completion/unused"}, .{});
        try std.testing.expect(unsubscription != staged);
        try client.flushPendingWithTimeout(.fromSeconds(3));
        var unsuback = try active.completeUnsubscribeWithTimeout(unsubscription, .fromSeconds(3));
        defer unsuback.deinit(allocator);
        try std.testing.expectEqual(staged, try client.completeNextPublish());
        try std.testing.expect(!active.hasOutgoingPacketIdentifier(staged));
        const publication = (try client.publishOneAttempt("completion/durable", "unconfirmed", .{ .qos = .at_least_once })).packet_id.?;
        client.disconnectTransport();
        const resumed = try client.connectWithTimeout(.fromSeconds(3));
        try std.testing.expect(resumed.session_present);
        var resumed_suback = try client.subscribeWithTimeout(&.{.{ .topic_filter = "completion/unused" }}, .{}, .fromSeconds(3));
        defer resumed_suback.deinit(allocator);
        try std.testing.expect(resumed_suback.suback.packet_id != publication);
        try std.testing.expectEqual(publication, try client.completeNextPublish());
        try std.testing.expectEqual(@as(u16, 0), client.connection().?.outgoing_inflight);
        try client.connection().?.disconnect(0);
    }
    std.debug.print("netz durable identifier interop passed: protocols=mqtt311,mqtt5 staged=true mixed-controls=true session-resume=true\n", .{});
}

fn exerciseSubscriptions(client: *mqtt.runtime.Connection, mode: Mode) !void {
    for ([_]bool{ false, true }) |unsubscribe| {
        const first = try writeControl(client, mode, unsubscribe, "completion/split-a");
        const second = try writeControl(client, mode, unsubscribe, "completion/split-b");
        try std.testing.expect(first != second);
        if (unsubscribe)
            try std.testing.expectError(error.Timeout, client.completeUnsubscribeWithTimeout(second, .zero))
        else
            try std.testing.expectError(error.Timeout, client.completeSubscribeWithTimeout(second, .zero));
        try std.testing.expect(client.hasOutgoingPacketIdentifier(second));
        // The external broker sends the first ACK first. Complete the second
        // request, then recover the first ACK from retained queue storage.
        try completeControl(client, mode, unsubscribe, second);
        try std.testing.expect(client.hasOutgoingPacketIdentifier(first));
        try completeControl(client, mode, unsubscribe, first);
        try std.testing.expect(!client.hasOutgoingPacketIdentifier(first));
        try std.testing.expect(!client.hasOutgoingPacketIdentifier(second));
        try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    }
}

fn writeControl(client: *mqtt.runtime.Connection, mode: Mode, unsubscribe: bool, filter: []const u8) !u16 {
    if (unsubscribe) return switch (mode) {
        .ordinary => client.writeUnsubscribe(&.{filter}, .{}),
        .timeout => client.writeUnsubscribeWithTimeout(&.{filter}, .{}, .fromSeconds(3)),
        .deadline => client.writeUnsubscribeWithDeadline(&.{filter}, .{}, client.transport.deadlineFromNow(.fromSeconds(3))),
    };
    return switch (mode) {
        .ordinary => client.writeSubscribe(&.{.{ .topic_filter = filter }}, .{}),
        .timeout => client.writeSubscribeWithTimeout(&.{.{ .topic_filter = filter }}, .{}, .fromSeconds(3)),
        .deadline => client.writeSubscribeWithDeadline(&.{.{ .topic_filter = filter }}, .{}, client.transport.deadlineFromNow(.fromSeconds(3))),
    };
}

fn completeControl(client: *mqtt.runtime.Connection, mode: Mode, unsubscribe: bool, id: u16) !void {
    if (unsubscribe) {
        var ack = switch (mode) {
            .ordinary => try client.completeUnsubscribe(id),
            .timeout => try client.completeUnsubscribeWithTimeout(id, .fromSeconds(3)),
            .deadline => try client.completeUnsubscribeWithDeadline(id, client.transport.deadlineFromNow(.fromSeconds(3))),
        };
        defer ack.deinit(client.allocator);
        try std.testing.expectEqual(id, ack.unsuback.packet_id);
        try std.testing.expectEqualSlices(u8, &.{0}, ack.unsuback.reason_codes);
    } else {
        var ack = switch (mode) {
            .ordinary => try client.completeSubscribe(id),
            .timeout => try client.completeSubscribeWithTimeout(id, .fromSeconds(3)),
            .deadline => try client.completeSubscribeWithDeadline(id, client.transport.deadlineFromNow(.fromSeconds(3))),
        };
        defer ack.deinit(client.allocator);
        try std.testing.expectEqual(id, ack.suback.packet_id);
        try std.testing.expectEqualSlices(u8, &.{0}, ack.suback.reason_codes);
    }
}

fn write(client: *mqtt.runtime.Connection, mode: Mode, payload: []const u8, qos: mqtt.QoS) !?u16 {
    return switch (mode) {
        .ordinary => client.writePublish("completion/self", payload, .{ .qos = qos }),
        .timeout => client.writePublishWithTimeout("completion/self", payload, .{ .qos = qos }, .fromSeconds(3)),
        .deadline => client.writePublishWithDeadline("completion/self", payload, .{ .qos = qos }, client.transport.deadlineFromNow(.fromSeconds(3))),
    };
}

fn complete(client: *mqtt.runtime.Connection, mode: Mode, packet_id: u16, qos: mqtt.QoS) !void {
    return switch (mode) {
        .ordinary => client.completePublish(packet_id, qos),
        .timeout => client.completePublishWithTimeout(packet_id, qos, .fromSeconds(3)),
        .deadline => client.completePublishWithDeadline(packet_id, qos, client.transport.deadlineFromNow(.fromSeconds(3))),
    };
}

fn expectDelivery(client: *mqtt.runtime.Connection, payload: []const u8) !void {
    var event = try client.readClientPacketEventWithTimeout(.fromSeconds(3));
    defer event.deinit(client.allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, event.publish.publish.qos);
    try std.testing.expectEqualStrings("completion/self", event.publish.publish.topic);
    try std.testing.expectEqualStrings(payload, event.publish.publish.payload);
}
