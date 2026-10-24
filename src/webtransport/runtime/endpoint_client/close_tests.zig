const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const control_mod = @import("../session_control.zig");
const Fixture = @import("test_support.zig").Fixture;
const ObservedSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

fn expectClose(fixture: *Fixture, id: u62, code: u32, reason: []const u8) !void {
    var control = try control_mod.Control.init(std.testing.allocator, .init(id));
    defer control.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(fixture.peer_endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    var header_read = false;
    while (true) {
        if (!header_read) {
            const bytes = fixture.peer.availableReceivedStream(id) orelse &.{};
            if (bytes.len != 0) {
                const frame = try http3.Frame.parse(bytes);
                try std.testing.expectEqual(http3.FrameType.headers, frame.frame_type);
                try fixture.peer.releaseReceivedCapacity(id, frame.consumed);
                header_read = true;
            }
        }
        if (header_read) {
            if (try control.pollOnce(&fixture.peer)) |event| {
                try std.testing.expect(event == .closed);
                try std.testing.expectEqual(code, event.closed.code);
                try std.testing.expectEqualStrings(reason, event.closed.reason);
                return;
            }
        }
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
}

test "WebTransport shared client CLOSE resumes after socket failure with exact metadata" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    const original_io = connection.endpoint.io;
    var observed = ObservedSend{ .delegate = original_io, .fail_on_call = 1 };
    var vtable = original_io.vtable.*;
    vtable.netSend = ObservedSend.netSend;
    connection.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
    {
        defer connection.endpoint.io = original_io;
        try std.testing.expectError(error.NetworkDown, session.close(&fixture.client, 77, "resumed"));
    }
    try std.testing.expect(!session.control.local_close_failed);
    try std.testing.expectError(error.InvalidSessionState, session.close(&fixture.client, 78, "changed"));
    try session.close(&fixture.client, 77, "resumed");
    try std.testing.expect(session.control.local_close_sent);
    try expectClose(&fixture, session.session_id.value, 77, "resumed");
    _ = try sibling.openBidirectionalStream(&fixture.client);
}

test "WebTransport shared client CLOSE resumes partial DATA framing without duplicate bytes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    const start = connection.sendStreamStats(session.session_id.value).?.highest_sent_offset;
    fixture.client.h3.options.max_stream_frame_data = 1;
    fixture.client.h3.options.max_frames_per_packet = 1;
    const original_io = connection.endpoint.io;
    var observed = ObservedSend{ .delegate = original_io, .fail_on_call = 3 };
    var vtable = original_io.vtable.*;
    vtable.netSend = ObservedSend.netSend;
    connection.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
    {
        defer connection.endpoint.io = original_io;
        try std.testing.expectError(error.NetworkDown, session.close(&fixture.client, 77, "tiny"));
    }
    try std.testing.expect(!session.control.local_close_failed);
    try std.testing.expectEqual(start + 2, connection.sendStreamStats(session.session_id.value).?.highest_sent_offset);
    try session.close(&fixture.client, 77, "tiny");
    try std.testing.expectEqual(start + 13, connection.sendStreamStats(session.session_id.value).?.highest_sent_offset);
    try expectClose(&fixture, session.session_id.value, 77, "tiny");
}

test "WebTransport shared client CLOSE deadline retains copied metadata and wire progress" {
    for ([_]bool{ false, true }) |absolute| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const connection = &fixture.client.h3.established.connection;
        const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, session.session_id.value);
        try quic.one_rtt.testing.applyReceivedFrames(connection, 91, &.{.{ .max_stream_data = .{ .stream_id = session.session_id.value, .maximum_stream_data = start + 1 } }}, null, .not_ect);
        var reason = [_]u8{'x'} ** 200;
        const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromMilliseconds(5) });
        if (absolute) try std.testing.expectError(error.Timeout, session.closeWithDeadline(&fixture.client, 79, &reason, deadline)) else try std.testing.expectError(error.Timeout, session.closeWithTimeout(&fixture.client, 79, &reason, .fromMilliseconds(5)));
        try std.testing.expect(session.close_state.pending != null and session.control.local_close_started);
        try std.testing.expect(!session.control.local_close_failed and !session.control.local_close_sent);
        try std.testing.expectEqual(@as(usize, 1), session.close_state.fragment.wire_sent);
        try std.testing.expectEqual(start + 1, connection.sendStreamStats(session.session_id.value).?.highest_sent_offset);
        @memset(&reason, 'z');
        try std.testing.expectError(error.InvalidSessionState, session.closeWithTimeout(&fixture.client, 79, &reason, .fromSeconds(1)));
        try fixture.queueDatagram(sibling, "sibling");
        var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .datagram);
        try std.testing.expectEqualStrings("sibling", event.datagram.payload);
        try quic.one_rtt.testing.applyReceivedFrames(connection, 92, &.{.{ .max_stream_data = .{ .stream_id = session.session_id.value, .maximum_stream_data = start + 1024 } }}, null, .not_ect);
        const original = [_]u8{'x'} ** 200;
        try session.closeWithTimeout(&fixture.client, 79, &original, .fromSeconds(1));
        try std.testing.expect(session.control.local_close_sent and session.close_state.pending == null);
        try expectClose(&fixture, session.session_id.value, 79, &original);
        const end = connection.sendStreamStats(session.session_id.value).?.highest_sent_offset;
        try session.closeWithTimeout(&fixture.client, 79, &original, .fromSeconds(1));
        try std.testing.expectEqual(end, connection.sendStreamStats(session.session_id.value).?.highest_sent_offset);
    }
}

test "WebTransport shared client CLOSE resumes from polling and removal with original metadata" {
    for ([_]bool{ false, true }) |remove| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = session.session_id;
        const connection = &fixture.client.h3.established.connection;
        fixture.client.h3.options.max_stream_frame_data = 1;
        fixture.client.h3.options.max_frames_per_packet = 1;
        const original_io = connection.endpoint.io;
        var observed = ObservedSend{ .delegate = original_io, .fail_on_call = 3 };
        var vtable = original_io.vtable.*;
        vtable.netSend = ObservedSend.netSend;
        connection.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
        {
            defer connection.endpoint.io = original_io;
            try std.testing.expectError(error.NetworkDown, session.close(&fixture.client, 77, "poll"));
        }
        if (remove) {
            try std.testing.expect(try fixture.client.removeSession(id));
        } else {
            for (0..32) |_| {
                if (session.close_state.pending == null) break;
                const before = connection.next_packet_number;
                try std.testing.expect((try fixture.poll(session)) == null);
                try std.testing.expect(connection.next_packet_number <= before + 1);
            }
            try std.testing.expect(session.close_state.pending == null and session.control.local_close_sent);
        }
        try expectClose(&fixture, id.value, 77, "poll");
        _ = try sibling.openBidirectionalStream(&fixture.client);
    }
}

test "WebTransport shared client CLOSE deadline cancels incomplete DATA on peer CLOSE" {
    for ([_]bool{ false, true }) |partial| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const connection = &fixture.client.h3.established.connection;
        const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, session.session_id.value);
        if (partial) try quic.one_rtt.testing.applyReceivedFrames(connection, 91, &.{.{ .max_stream_data = .{ .stream_id = session.session_id.value, .maximum_stream_data = start + 1 } }}, null, .not_ect);
        try std.testing.expectError(error.Timeout, session.closeWithTimeout(&fixture.client, 79, "local", .fromMilliseconds(5)));
        try fixture.close(session, &.{});
        try session.closeWithTimeout(&fixture.client, 79, "local", .fromSeconds(1));
        try std.testing.expect(session.close_state.pending == null);
        const stats = connection.sendStreamStats(session.session_id.value).?;
        if (partial) {
            try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, stats.reset.?.application_error_code);
            try std.testing.expectEqual(start + 1, stats.highest_sent_offset);
        } else try std.testing.expectEqual(@as(?u64, start), stats.final_size);
        var event = (try fixture.poll(session)) orelse return error.TestUnexpectedResult;
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .session and event.session == .closed);
        try std.testing.expectEqual(@as(u32, 77), event.session.closed.code);
        try std.testing.expectEqualStrings("done", event.session.closed.reason);
        _ = try sibling.openBidirectionalStream(&fixture.client);
    }
}

test "WebTransport shared client CLOSE deadline receives connection termination across sessions" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    try fixture.queueDatagram(sibling, "discarded");
    try fixture.peer.closeApplication(99, "done");
    fixture.client.h3.established.connection.congestion.congestion_window = 0;
    try std.testing.expectError(error.ConnectionClosed, session.closeWithTimeout(&fixture.client, 79, "local", .fromSeconds(1)));
    try std.testing.expect(session.close_state.pending == null);
    try std.testing.expect(session.control.connection_terminated and sibling.control.connection_terminated);
    try std.testing.expectEqual(@as(usize, 0), try fixture.client.h3.connect_datagrams.queuedCount(sibling.session_id.value));
}

test "WebTransport shared client CLOSE validation and allocation failures leave Session usable" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    const before = connection.next_packet_number;
    const too_long = [_]u8{'x'} ** 1025;
    try std.testing.expectError(error.InvalidCapsule, session.closeWithTimeout(&fixture.client, 79, &too_long, .fromSeconds(1)));
    try std.testing.expectError(error.InvalidCapsule, session.closeWithTimeout(&fixture.client, 79, "\xff", .fromSeconds(1)));
    try std.testing.expectError(error.Timeout, session.closeWithTimeout(&fixture.client, 79, "", .zero));
    const expired = std.Io.Clock.Timestamp{ .clock = .awake, .raw = .zero };
    try std.testing.expectError(error.Timeout, session.closeWithDeadline(&fixture.client, 79, "", expired));
    var clone = session.*;
    try std.testing.expectError(error.InvalidSessionState, clone.closeWithTimeout(&fixture.client, 79, "", .fromSeconds(1)));
    fixture.client.h3.callback_reader_active = true;
    try std.testing.expectError(error.ConcurrentRead, session.closeWithTimeout(&fixture.client, 79, "", .fromSeconds(1)));
    fixture.client.h3.callback_reader_active = false;
    fixture.client.h3.dispatcher_bound = true;
    try std.testing.expectError(error.InvalidDispatcherState, session.closeWithTimeout(&fixture.client, 79, "", .fromSeconds(1)));
    fixture.client.h3.dispatcher_bound = false;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const reason = [_]u8{'x'} ** 200;
    {
        fixture.client.h3.allocator = failing.allocator();
        defer fixture.client.h3.allocator = std.testing.allocator;
        try std.testing.expectError(error.OutOfMemory, session.closeWithTimeout(&fixture.client, 79, &reason, .fromSeconds(1)));
    }
    try std.testing.expectEqual(before, connection.next_packet_number);
    try std.testing.expect(session.close_state.pending == null and !session.control.local_close_started);
    _ = try session.openBidirectionalStream(&fixture.client);
}

test "WebTransport shared client CLOSE retries associated cleanup without replaying the capsule" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const stream = try session.openBidirectionalStream(&fixture.client);
    const connection = &fixture.client.h3.established.connection;
    try quic.one_rtt.testing.applyReceivedFrames(connection, 91, &.{.{ .stream = .{ .stream_id = stream, .data = "reverse" } }}, null, .not_ect);
    const original_io = connection.endpoint.io;
    var observed = ObservedSend{ .delegate = original_io, .fail_on_call = 2 };
    var vtable = original_io.vtable.*;
    vtable.netSend = ObservedSend.netSend;
    connection.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
    {
        defer connection.endpoint.io = original_io;
        try std.testing.expectError(error.NetworkDown, session.closeWithTimeout(&fixture.client, 77, "cleanup", .fromSeconds(1)));
    }
    try std.testing.expect(session.control.local_close_sent and session.close_state.pending == null);
    const end = connection.sendStreamStats(session.session_id.value).?.highest_sent_offset;
    try session.closeWithTimeout(&fixture.client, 77, "cleanup", .fromSeconds(1));
    try std.testing.expectEqual(end, connection.sendStreamStats(session.session_id.value).?.highest_sent_offset);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.sendStreamStats(stream).?.reset.?.application_error_code);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.recvStreamStats(stream).?.stop_sending_sent.?.application_error_code);
    try expectClose(&fixture, session.session_id.value, 77, "cleanup");
    _ = try sibling.openBidirectionalStream(&fixture.client);
}

test "WebTransport shared client CLOSE acknowledges an already observed peer close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    const before = connection.sendStreamStats(session.session_id.value).?.highest_sent_offset;
    try fixture.close(session, &.{});
    try fixture.expectClose(session);
    try session.closeWithTimeout(&fixture.client, 79, "local", .fromSeconds(1));
    try std.testing.expectEqual(@as(?u64, before), connection.sendStreamStats(session.session_id.value).?.final_size);
    try std.testing.expectEqual(@as(?u32, 77), session.control.state.close_code);
    try std.testing.expect(session.close_state.pending == null);
    _ = try sibling.openBidirectionalStream(&fixture.client);
}
