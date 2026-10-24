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
    std.debug.print("netz synchronous publish interop passed: protocols=mqtt31,mqtt311,mqtt5 qos=1,2 reverse-completion=true self-delivery=true wire-order=true budgets=ordinary,timeout,deadline client_io=zio-std-io server_io=mosquitto\n", .{});
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
