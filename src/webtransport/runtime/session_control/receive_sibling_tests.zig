//! Peer CONNECT termination must preserve other Sessions on the same owner.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");

fn endSend(connection: *quic.one_rtt.Connection, id: u62, reset: bool) !void {
    if (reset) {
        try connection.tryResetStream(id, webtransport.ApplicationErrorCode.session_gone);
    } else {
        try connection.send(&.{.{ .stream = .{
            .stream_id = id,
            .offset = connection.sendStreamStats(id).?.highest_sent_offset,
            .data = &.{},
            .fin = true,
        } }});
    }
}

test "WebTransport CONNECT peer FIN and RESET preserve shared client siblings during close cleanup" {
    const Fixture = @import("../endpoint_client/test_support.zig").Fixture;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |reset| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const affected = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = affected.session_id.value;
        const stream_id = try affected.openBidirectionalStream(&fixture.client);
        try endSend(&fixture.peer, id, reset);
        const connection = &fixture.client.h3.established.connection;
        const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (connection.recvStreamStats(id).?.final_size == null) try fixture.client.h3.receiveDetachedResponseProgressWithDeadline(id, deadline);
        try std.testing.expectError(error.InvalidSessionState, affected.openBidirectionalStream(&fixture.client));
        try std.testing.expectError(error.InvalidSessionState, affected.sendDatagram(&fixture.client, "late"));
        try affected.closeWithTimeout(&fixture.client, 999, "cleanup", .fromSeconds(1));
        var event = (try fixture.poll(affected)) orelse return error.TestUnexpectedResult;
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .session);
        try std.testing.expect(if (reset) event.session == .reset else event.session == .closed);
        if (reset) {
            try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), event.session.reset.http3_code);
        } else {
            try std.testing.expectEqual(@as(u32, 0), event.session.closed.code);
        }
        for (0..4) |_| try std.testing.expect((try fixture.poll(affected)) == null);
        try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), affected.streams.get(stream_id).?.send_reset.?.http3_code);
        try fixture.queueDatagram(sibling, "sibling");
        var received = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
        defer received.deinit(std.testing.allocator);
        try std.testing.expect(received == .datagram);
        try std.testing.expectEqualStrings("sibling", received.datagram.payload);
        try sibling.sendDatagram(&fixture.client, "still open");
        _ = try sibling.openBidirectionalStream(&fixture.client);
        try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
    }
}

test "WebTransport CONNECT peer FIN and RESET preserve shared server siblings during close cleanup" {
    const Fixture = @import("../endpoint_server/test_support.zig").Fixture;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |reset| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const affected = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = affected.session_id.value;
        const stream_id = try fixture.openPeerStream(affected);
        try endSend(&fixture.client.established.connection, id, reset);
        const connection = &fixture.connectionSession().established.connection;
        while (connection.recvStreamStats(id).?.final_size == null) try fixture.routeTransport();
        try std.testing.expectError(error.InvalidSessionState, affected.openBidirectionalStream());
        try std.testing.expectError(error.InvalidSessionState, affected.sendDatagram("late"));
        try affected.close(999, "cleanup");
        var output: [16]u8 = undefined;
        const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(affected, &output)) orelse return error.TestUnexpectedResult;
        try std.testing.expect(event == .session);
        try std.testing.expect(if (reset) event.session == .reset else event.session == .closed);
        if (reset) {
            try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), event.session.reset.http3_code);
        } else {
            try std.testing.expectEqual(@as(u32, 0), event.session.closed.code);
        }
        for (0..4) |_| try std.testing.expect((try runtime.EndpointServer.testing.pollAcceptedSessionEntry(affected, &output)) == null);
        const stream = affected.streams.get(stream_id).?;
        try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.send_reset.?.http3_code);
        try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.stop_sent.?.http3_code);
        try sibling.sendDatagram("still open");
        _ = try sibling.openBidirectionalStream();
        try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
        try std.testing.expect(fixture.endpoint.sessionById(fixture.handle, sibling.session_id) == sibling);
    }
}
