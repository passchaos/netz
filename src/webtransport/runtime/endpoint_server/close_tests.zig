const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const Fixture = @import("test_support.zig").Fixture;
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

test "WebTransport shared server tiny CLOSE completes with a one-byte frame budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = accepted.session_id;
    const h3 = fixture.connectionSession();
    h3.options.max_frames_per_packet = 1;
    h3.options.max_stream_frame_data = 1;
    try accepted.close(94, "tiny");
    try std.testing.expect(accepted.control.local_close_sent);
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try fixture.expectPeerClosed(id, 94);
    try fixture.client.sendConnectDatagram(sibling.session_id.value, "alive");
    var output: [16]u8 = undefined;
    var event = try fixture.receive(&output);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .session_event and event.session_event.event == .datagram);
    try std.testing.expectEqualStrings("alive", event.session_event.event.datagram.datagram.payload);
}

test "WebTransport shared server tiny removal closes its CONNECT before release" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const id = accepted.session_id;
    const h3 = fixture.connectionSession();
    const start = h3.established.connection.sendStreamStats(id.value).?.highest_sent_offset;
    h3.options.max_frames_per_packet = 1;
    h3.options.max_stream_frame_data = 1;
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try std.testing.expectEqual(start + 9, h3.established.connection.sendStreamStats(id.value).?.highest_sent_offset);
    try fixture.expectPeerClosed(id, 0);
}

test "WebTransport shared server tiny CLOSE preserves a submitted DATA header after failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const id = accepted.session_id;
    const h3 = fixture.connectionSession();
    h3.options.max_frames_per_packet = 1;
    h3.options.max_stream_frame_data = 1;
    const connection = &h3.established.connection;
    const start = connection.sendStreamStats(id.value).?.highest_sent_offset;
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 3 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, accepted.close(93, "small"));
    try std.testing.expectEqual(start + 2, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try std.testing.expect(accepted.control.local_close_started);
    connection.endpoint.io = original_io;
    try std.testing.expectError(error.InvalidSessionState, accepted.close(99, "different"));
    try accepted.close(93, "small");
    try std.testing.expectEqual(start + 14, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try fixture.expectPeerClosed(id, 93);
}

test "WebTransport shared server tiny CLOSE progresses from endpoint polling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const id = accepted.session_id;
    const h3 = fixture.connectionSession();
    h3.options.max_frames_per_packet = 1;
    h3.options.max_stream_frame_data = 1;
    const connection = &h3.established.connection;
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 3 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, accepted.close(93, "poll"));
    connection.endpoint.io = original_io;
    var output: [16]u8 = undefined;
    var polls: usize = 0;
    while (accepted.pending_close != null) : (polls += 1) {
        try std.testing.expect(polls < 20);
        const before = connection.next_packet_number;
        try std.testing.expect((try @import("../../runtime.zig").EndpointServer.testing.pollAcceptedSessionEntry(accepted, &output)) == null);
        try std.testing.expect(connection.next_packet_number <= before + 1);
    }
    try std.testing.expect(accepted.control.local_close_sent);
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try fixture.expectPeerClosed(id, 93);
}

test "WebTransport shared server tiny CLOSE cancels its partial frame when the peer closes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = accepted.session_id;
    const h3 = fixture.connectionSession();
    h3.options.max_frames_per_packet = 1;
    h3.options.max_stream_frame_data = 1;
    const connection = &h3.established.connection;
    const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, id.value);
    try fixture.client.established.connection.send(&.{.{ .max_stream_data = .{ .stream_id = id.value, .maximum_stream_data = start + 1 } }});
    while (connection.streamSendAvailable(id.value) == 0) try fixture.routeTransport();
    try std.testing.expectError(error.FlowControlBlocked, accepted.close(95, "pending"));
    try std.testing.expectEqual(start + 1, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try fixture.closePeer(accepted, "peer", &.{});
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.sendStreamStats(id.value).?.reset.?.application_error_code);
    try std.testing.expectEqual(start + 1, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try std.testing.expect(fixture.endpoint.sessionById(fixture.handle, sibling.session_id) == sibling);
    try std.testing.expect(!connection.closed());
}

test "WebTransport shared server tiny CLOSE frees pending heap storage on teardown" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const h3 = fixture.connectionSession();
    h3.options.max_frames_per_packet = 1;
    h3.options.max_stream_frame_data = 1;
    const connection = &h3.established.connection;
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    const reason = [_]u8{'h'} ** 200;
    try std.testing.expectError(error.NetworkDown, accepted.close(96, &reason));
    try std.testing.expect(accepted.pending_close != null and accepted.pending_close.?.storage == .heap);
}

test "WebTransport shared server tiny CLOSE releases pending data on connection termination" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const h3 = fixture.connectionSession();
    const connection = &h3.established.connection;
    const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, accepted.session_id.value);
    try std.testing.expectError(error.FlowControlBlocked, accepted.close(97, "end"));
    connection.failClosedApplication(18, "connection ended");
    const before = connection.next_packet_number;
    try accepted.close(97, "end");
    try std.testing.expect(accepted.pending_close == null);
    try std.testing.expectEqual(before, connection.next_packet_number);
    try std.testing.expectEqual(start, connection.sendStreamStats(accepted.session_id.value).?.highest_sent_offset);
}

test "WebTransport shared server tiny CLOSE prioritizes post-CLOSE rejection over its pending frame" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const h3 = fixture.connectionSession();
    h3.options.max_frames_per_packet = 1;
    h3.options.max_stream_frame_data = 1;
    const connection = &h3.established.connection;
    const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, accepted.session_id.value);
    try fixture.client.established.connection.send(&.{.{ .max_stream_data = .{ .stream_id = accepted.session_id.value, .maximum_stream_data = start + 1 } }});
    while (connection.streamSendAvailable(accepted.session_id.value) == 0) try fixture.routeTransport();
    try std.testing.expectError(error.FlowControlBlocked, accepted.close(95, "pending"));
    try fixture.closePeer(accepted, "peer", &.{0xff});
    try accepted.close(95, "pending");
    try std.testing.expect(accepted.pending_close == null);
    try std.testing.expectEqual(@import("../../../http3/mod.zig").ApplicationErrorCode.message_error, connection.sendStreamStats(accepted.session_id.value).?.reset.?.application_error_code);
    try std.testing.expectEqual(start + 1, connection.sendStreamStats(accepted.session_id.value).?.highest_sent_offset);
}

test "WebTransport shared server tiny removal keeps forbidden CONNECT errors at connection scope" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const connection = &fixture.connectionSession().established.connection;
    const offset = connection.recvStreamStats(accepted.session_id.value).?.highest_received_offset;
    try quic.one_rtt.testing.applyReceivedFrames(connection, 90, &.{.{ .stream = .{ .stream_id = accepted.session_id.value, .offset = offset, .data = &.{ 1, 0 } } }}, null, .not_ect);
    try std.testing.expectError(error.UnexpectedFrame, fixture.endpoint.removeSession(fixture.handle, accepted.session_id));
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(@import("../../../http3/mod.zig").ApplicationErrorCode.frame_unexpected, quic.one_rtt.testing.localCloseInfo(connection).?.error_code);
}

test "WebTransport shared server tiny removal resumes the original heap-backed CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const id = accepted.session_id;
    const h3 = fixture.connectionSession();
    h3.options.max_frames_per_packet = 1;
    h3.options.max_stream_frame_data = 16;
    const connection = &h3.established.connection;
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 2 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    const reason = [_]u8{'h'} ** 200;
    try std.testing.expectError(error.NetworkDown, accepted.close(96, &reason));
    try std.testing.expect(accepted.pending_close != null and accepted.pending_close.?.storage == .heap);
    connection.endpoint.io = original_io;
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try std.testing.expect(!h3.request_lifecycle.contains(id.value));
    try fixture.expectPeerClosed(id, 96);
}

test "WebTransport shared server tiny CLOSE replies with FIN when the peer closes before any write" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const accepted = try fixture.addSession();
    const id = accepted.session_id;
    const connection = &fixture.connectionSession().established.connection;
    const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, id.value);
    try std.testing.expectError(error.FlowControlBlocked, accepted.close(98, "blocked"));
    try std.testing.expectEqual(start, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try fixture.closePeer(accepted, "peer", &.{});
    try std.testing.expect(try fixture.endpoint.removeSession(fixture.handle, id));
    try std.testing.expectEqual(@as(?u64, start), connection.sendStreamStats(id.value).?.final_size);
    try std.testing.expect(!connection.closed());
}
