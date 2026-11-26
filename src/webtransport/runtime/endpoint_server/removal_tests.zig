const std = @import("std");
const webtransport = @import("../../mod.zig");
const Fixture = @import("test_support.zig").Fixture;
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

test "WebTransport endpoint server removal releases heap-backed CLOSE reasons" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const Path = enum { session, connection, endpoint };
    for ([_]Path{ .session, .connection, .endpoint }) |path| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const accepted = try fixture.addSession();
        const id = accepted.session_id;
        const reason = [_]u8{'r'} ** 200;
        try fixture.closePeer(accepted, &reason, &.{});
        try std.testing.expect(accepted.control.close_reason_heap != null);
        switch (path) {
            .session => try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id)),
            .connection => try std.testing.expect(fixture.endpoint.removeConnection(fixture.handle)),
            .endpoint => {
                fixture.endpoint.deinit();
                fixture.endpoint_owned = false;
            },
        }
    }
}

test "WebTransport endpoint server removal terminates a registered stream before forgetting it" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = accepted.session_id;
    const stream = try fixture.openPeerStream(accepted);
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    const connection = &fixture.connectionSession().established.connection;
    try std.testing.expect(connection.sendStreamStats(stream).?.reset != null);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.sendStreamStats(stream).?.reset.?.application_error_code);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.recvStreamStats(stream).?.stop_sending_sent.?.application_error_code);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.recvStreamStats(id.value).?.stop_sending_sent.?.application_error_code);
    try std.testing.expect(fixture.endpoint.sessionById(fixture.handle, id) == null);
    try std.testing.expect(fixture.endpoint.sessionById(fixture.handle, sibling.session_id) == sibling);
    try std.testing.expect(!connection.closed());
    try fixture.expectPeerClosed(id, 0);
    try fixture.client.sendConnectDatagram(sibling.session_id.value, "after remove");
    var output: [32]u8 = undefined;
    var event = try fixture.receive(&output);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .session_event and event.session_event.session_id.value == sibling.session_id.value and event.session_event.event == .datagram);
    try std.testing.expectEqualStrings("after remove", event.session_event.event.datagram.datagram.payload);
}

test "WebTransport endpoint server removal keeps its owner when rejection send fails" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    _ = try fixture.addSession();
    try fixture.closePeer(accepted, "done", &.{0xff});
    const connection = &fixture.connectionSession().established.connection;
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.endpoint.removeSession(fixture.handle, accepted.session_id));
    try std.testing.expect(fixture.endpoint.sessionById(fixture.handle, accepted.session_id) == accepted);
    try std.testing.expectEqual(@as(usize, 2), fixture.endpoint.sessionCount());
    try std.testing.expect(!accepted.control.local_close_sent);
    const id = accepted.session_id;
    connection.endpoint.io = original_io;
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try std.testing.expectEqual(@import("../../../http3/mod.zig").ApplicationErrorCode.message_error, connection.sendStreamStats(id.value).?.reset.?.application_error_code);
    try std.testing.expectEqual(@import("../../../http3/mod.zig").ApplicationErrorCode.message_error, connection.recvStreamStats(id.value).?.stop_sending_sent.?.application_error_code);
}

test "WebTransport endpoint server removal drains an unclaimed FIN stream before release" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const id = accepted.session_id;
    const stream = try fixture.unclaimedFinStream(id);
    const connection = &fixture.connectionSession().established.connection;
    try std.testing.expect(accepted.streams.get(stream) == null);
    try std.testing.expectEqual(@as(u64, 0), connection.recvStreamStats(stream).?.bytes_read);
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try std.testing.expect(connection.streamLifecycle(stream) == .closed or connection.recvStreamStats(stream).?.bytes_read >= 9);
}

test "WebTransport endpoint server removal resumes after CLOSE without replaying its bytes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = accepted.session_id;
    _ = try fixture.openPeerStream(accepted);
    const connection = &fixture.connectionSession().established.connection;
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 2 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.endpoint.removeSession(fixture.handle, id));
    try std.testing.expect(fixture.endpoint.sessionById(fixture.handle, id) == accepted);
    try std.testing.expect(accepted.control.local_close_sent);
    const close_end = connection.sendStreamStats(id.value).?.highest_sent_offset;
    connection.endpoint.io = original_io;
    try fixture.client.sendConnectDatagram(sibling.session_id.value, "sibling");
    var output: [16]u8 = undefined;
    var event = try fixture.receive(&output);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .session_event and event.session_event.session_id.value == sibling.session_id.value and event.session_event.event == .datagram);
    try std.testing.expectEqualStrings("sibling", event.session_event.event.datagram.datagram.payload);
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try std.testing.expectEqual(close_end, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try std.testing.expectEqual(@as(usize, 1), fixture.endpoint.sessionCount());
}

test "WebTransport endpoint server removal accepts an already-stopped CONNECT sender" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = accepted.session_id;
    const stream = try fixture.openPeerStream(accepted);
    try fixture.client.established.connection.sendStopSending(id.value, webtransport.ApplicationErrorCode.session_gone);
    const connection = &fixture.connectionSession().established.connection;
    while (connection.sendStreamStats(id.value).?.stopped == null) try fixture.routeTransport();
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try std.testing.expect(fixture.endpoint.sessionById(fixture.handle, id) == null);
    try std.testing.expect(connection.sendStreamStats(stream).?.reset != null);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.recvStreamStats(stream).?.stop_sending_sent.?.application_error_code);
    try fixture.client.sendConnectDatagram(sibling.session_id.value, "alive");
    var output: [16]u8 = undefined;
    var event = try fixture.receive(&output);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .session_event and event.session_event.event == .datagram);
    try std.testing.expectEqualStrings("alive", event.session_event.event.datagram.datagram.payload);
}

test "WebTransport endpoint server local CLOSE hides queued data while keeping sibling progress" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const sibling = try fixture.addSession();
    _ = try fixture.openPeerStream(accepted);
    try accepted.close(81, "done");
    try fixture.client.established.connection.send(&.{
        .{ .datagram = .{ .data = "\x00late" } },
        .{ .datagram = .{ .data = "\x01alive" } },
    });
    const h3 = fixture.connectionSession();
    while (try h3.connect_datagrams.queuedCount(sibling.session_id.value) == 0) try fixture.routeTransport();
    try std.testing.expectEqual(@as(usize, 0), try h3.connect_datagrams.queuedCount(accepted.session_id.value));
    var output: [16]u8 = undefined;
    for (0..4) |_| try std.testing.expect((try @import("../../runtime.zig").EndpointServer.testing.pollAcceptedSessionEntry(accepted, &output)) == null);
    var event = try fixture.receive(&output);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .session_event and event.session_event.session_id.value == sibling.session_id.value and event.session_event.event == .datagram);
    try std.testing.expectEqualStrings("alive", event.session_event.event.datagram.datagram.payload);
}

test "WebTransport endpoint server removal completes after peer CONNECT reset" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = accepted.session_id;
    const stream = try fixture.openPeerStream(accepted);
    try fixture.client.established.connection.tryResetStream(id.value, @import("../../../http3/mod.zig").ApplicationErrorCode.request_cancelled);
    const connection = &fixture.connectionSession().established.connection;
    while (connection.recvStreamStats(id.value).?.reset == null) try fixture.routeTransport();
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    const send = connection.sendStreamStats(id.value).?;
    try std.testing.expect(send.final_size != null or send.reset != null);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.sendStreamStats(stream).?.reset.?.application_error_code);
    try fixture.client.sendConnectDatagram(sibling.session_id.value, "after reset");
    var output: [16]u8 = undefined;
    var event = try fixture.receive(&output);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .session_event and event.session_event.event == .datagram);
    try std.testing.expectEqualStrings("after reset", event.session_event.event.datagram.datagram.payload);
}
