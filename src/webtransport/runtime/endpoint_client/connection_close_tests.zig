const std = @import("std");
const Fixture = @import("test_support.zig").Fixture;
const Client = @import("../endpoint_client.zig").Client;

test "WebTransport endpoint client bounds connection close before state access" {
    var client: Client = undefined;
    const reason = [_]u8{'x'} ** 1025;
    try std.testing.expectError(error.InvalidSessionState, client.closeConnection(99, &reason));
}

fn expectAllClosed(fixture: *Fixture, ids: []const u62) !void {
    const packet_number = fixture.client.h3.established.connection.next_packet_number;
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(error.ConnectionClosed, fixture.client.pollAny(&buffer));
    for (ids) |id| {
        const session = fixture.client.session(.init(id)).?;
        try std.testing.expect(session.control.connection_terminated and session.control.state.closed);
        try std.testing.expectError(error.ConnectionClosed, session.sendDatagram(&fixture.client, "late"));
        try std.testing.expectError(error.ConnectionClosed, session.openBidirectionalStream(&fixture.client));
        try std.testing.expectEqual(@as(usize, 0), try fixture.client.h3.connect_datagrams.queuedCount(id));
    }
    try std.testing.expectError(error.ConnectionClosed, fixture.client.openSession(.{
        .authority = "localhost",
        .path = "/after-close",
        .origin = "https://localhost",
    }));
    for (ids) |id| try std.testing.expect(try fixture.client.removeSession(.init(id)));
    try std.testing.expectEqual(@as(usize, 0), fixture.client.sessionCount());
    try std.testing.expectEqual(packet_number, fixture.client.h3.established.connection.next_packet_number);
}

test "WebTransport endpoint client closes all sessions and queues on local QUIC close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    const ids = [_]u62{ first.session_id.value, second.session_id.value };
    try fixture.queueDatagram(first, "first");
    try fixture.queueDatagram(second, "second");
    try fixture.client.closeConnection(99, "all sessions");
    try std.testing.expect(first.control.state.closed and second.control.state.closed);
    try expectAllClosed(&fixture, &ids);
}

test "WebTransport endpoint client drops buffered events after peer QUIC close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    const ids = [_]u62{ first.session_id.value, second.session_id.value };
    try fixture.queueDatagram(first, "first");
    try fixture.queueDatagram(second, "second");
    try fixture.peer.closeApplication(99, "all sessions");
    var packet = try fixture.client.h3.established.connection.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
    defer packet.deinit(std.testing.allocator);
    try fixture.client.h3.processDetachedResponsePacket(ids[0], &packet);
    try expectAllClosed(&fixture, &ids);
    const close = fixture.client.h3.established.connection.peerCloseInfo().?;
    try std.testing.expect(close == .application);
    try std.testing.expectEqual(@as(u64, 99), close.application.error_code);
    try std.testing.expectEqualStrings("all sessions", close.application.reason_phrase);
}
