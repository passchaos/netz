const std = @import("std");
const mqtt = @import("../../mod.zig");
const reconnect = @import("../../reconnect.zig");
const Pair = @import("../../runtime/acknowledgement/test_connection.zig").Pair;
const allocator = std.testing.allocator;

test "MQTT automatic release rejects PUBREL before manual PUBREC instead of retaining an invalid event" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        var shutdown: std.Io.Event = .unset;
        var client = try reconnect.Client.initWithOptions(allocator, io, .{ .ip4 = .loopback(1) }, .{ .protocol = protocol, .client_id = "early-release" }, .{}, &shutdown, .{ .manual_acknowledgements = true });
        defer client.deinit();
        const pair = try Pair.init(io, protocol);
        client.connection_state = pair.client;
        var peer = pair.peer;
        defer peer.close();
        const id = (try peer.writePublish("manual/pending", "not acknowledged", .{ .qos = .exactly_once })).?;
        var publication = (try client.pollWithTimeout(.fromSeconds(1))).?;
        defer publication.deinit(allocator);
        try std.testing.expect(publication == .publish);
        try peer.writePubRel(id, 0);
        try std.testing.expectError(error.UnexpectedPacket, client.pollWithTimeout(.fromSeconds(1)));
        try std.testing.expect(client.connection() == null);
        try std.testing.expect(client.pending_event == null);
        if (protocol == .v5) {
            var diagnostic = try peer.readDisconnect();
            defer diagnostic.deinit(allocator);
            try std.testing.expectEqual(@as(u8, 0x82), diagnostic.disconnect.reason_code);
        }
    }
}
