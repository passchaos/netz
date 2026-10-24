const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

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

        for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| {
            const first = (try client.writePublish("completion/self", "first", .{ .qos = qos })).?;
            const second = (try client.writePublish("completion/self", "second", .{ .qos = qos })).?;
            // Mosquitto sends initial acknowledgements in order. Deliberately
            // complete the second first to exercise preservation and later
            // extraction of the first ACK alongside self-delivered messages.
            try client.completePublish(second, qos);
            try client.completePublish(first, qos);
            try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
            const expected = if (qos == .exactly_once)
                [_][]const u8{ "second", "first" }
            else
                [_][]const u8{ "first", "second" };
            for (expected) |payload| try expectDelivery(&client, payload);

            // The ordinary synchronous convenience method has the same
            // interleaved receive contract as split publish completion.
            try client.publish("completion/self", "ordinary", .{ .qos = qos });
            try expectDelivery(&client, "ordinary");
        }
        try client.pingWithTimeout(.fromSeconds(3));
        try client.disconnect(0);
    }
    std.debug.print("netz synchronous publish interop passed: protocols=mqtt31,mqtt311,mqtt5 qos=1,2 reverse-completion=true self-delivery=true wire-order=true client_io=zio-std-io server_io=mosquitto\n", .{});
}

fn expectDelivery(client: *mqtt.runtime.Connection, payload: []const u8) !void {
    var event = try client.readClientPacketEventWithTimeout(.fromSeconds(3));
    defer event.deinit(client.allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, event.publish.publish.qos);
    try std.testing.expectEqualStrings("completion/self", event.publish.publish.topic);
    try std.testing.expectEqualStrings(payload, event.publish.publish.payload);
}
