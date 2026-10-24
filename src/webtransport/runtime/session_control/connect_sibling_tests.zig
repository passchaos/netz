//! Session-scoped CONNECT termination over multiplexed client/server owners.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const webtransport = @import("../../mod.zig");

test "WebTransport CONNECT STOP_SENDING preserves shared client sibling streams and datagrams" {
    const Fixture = @import("../endpoint_client/test_support.zig").Fixture;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const affected = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = affected.session_id.value;
    const stream_id = try affected.openBidirectionalStream(&fixture.client);
    try fixture.queueDatagram(affected, "queued");
    try fixture.peer.trySendStopSending(id, webtransport.ApplicationErrorCode.session_gone);
    const connection = &fixture.client.h3.established.connection;
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (connection.sendStreamStats(id).?.stopped == null) try fixture.client.h3.receiveDetachedResponseProgressWithDeadline(id, deadline);
    try std.testing.expect(connection.recvStreamStats(id).?.final_size == null);
    try std.testing.expectError(error.InvalidSessionState, affected.openBidirectionalStream(&fixture.client));
    try std.testing.expectError(error.InvalidSessionState, affected.sendDatagram(&fixture.client, "late"));
    var event = (try fixture.poll(affected)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .session and event.session == .reset);
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

test "WebTransport CONNECT STOP_SENDING preserves shared server sibling streams and datagrams" {
    const Fixture = @import("../endpoint_server/test_support.zig").Fixture;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const affected = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = affected.session_id.value;
    const stream_id = try fixture.openPeerStream(affected);
    try fixture.client.established.connection.trySendStopSending(id, webtransport.ApplicationErrorCode.session_gone);
    const connection = &fixture.connectionSession().established.connection;
    while (connection.sendStreamStats(id).?.stopped == null) try fixture.routeTransport();
    try std.testing.expect(connection.recvStreamStats(id).?.final_size == null);
    try std.testing.expectError(error.InvalidSessionState, affected.openBidirectionalStream());
    try std.testing.expectError(error.InvalidSessionState, affected.sendDatagram("late"));
    var output: [16]u8 = undefined;
    const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(affected, &output)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .session and event.session == .reset);
    for (0..4) |_| try std.testing.expect((try runtime.EndpointServer.testing.pollAcceptedSessionEntry(affected, &output)) == null);
    const stream = affected.streams.get(stream_id).?;
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.send_reset.?.http3_code);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.stop_sent.?.http3_code);
    try sibling.sendDatagram("still open");
    _ = try sibling.openBidirectionalStream();
    try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
    try std.testing.expect(fixture.endpoint.sessionById(fixture.handle, sibling.session_id) == sibling);
}

test "WebTransport CONNECT STOP_SENDING preserves shared server buffered CLOSE without replying FIN" {
    const Fixture = @import("../endpoint_server/test_support.zig").Fixture;
    const control = @import("../session_control.zig");
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const affected = try fixture.addSession();
    const id = affected.session_id.value;
    var bytes: [64]u8 = undefined;
    const close = try control.writeCloseInto(&bytes, 77, "buffered close");
    try fixture.client.sendRequestBodyPaced(id, close, false);
    try fixture.client.established.connection.trySendStopSending(id, webtransport.ApplicationErrorCode.session_gone);
    const connection = &fixture.connectionSession().established.connection;
    while (connection.sendStreamStats(id).?.stopped == null) try fixture.routeTransport();
    var output: [16]u8 = undefined;
    const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(affected, &output)).?;
    try std.testing.expect(event == .session and event.session == .closed);
    try std.testing.expectEqual(@as(u32, 77), event.session.closed.code);
    try std.testing.expectEqualStrings("buffered close", event.session.closed.reason);
    try std.testing.expect(!affected.close_response_pending);
    try std.testing.expect((try runtime.EndpointServer.testing.pollAcceptedSessionEntry(affected, &output)) == null);
    try std.testing.expect(affected.control.local_close_failed and !affected.control.local_close_sent);
}
