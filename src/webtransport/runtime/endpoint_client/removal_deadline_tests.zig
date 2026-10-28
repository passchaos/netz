const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const http3 = @import("../../../http3/mod.zig");
const control_mod = @import("../session_control.zig");
const Fixture = @import("test_support.zig").Fixture;
const allocator = std.testing.allocator;

fn expectPeerClose(fixture: *Fixture, id: u62, code: u32, reason: []const u8) !void {
    var control = try control_mod.Control.init(allocator, .init(id));
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
        packet.deinit(allocator);
    }
}

test "WebTransport endpoint client removal deadline retains partial CLOSE and sibling ownership" {
    for ([_]bool{ false, true }) |absolute| {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = session.session_id;
        const connection = &fixture.client.h3.established.connection;
        const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, id.value);
        try quic.one_rtt.testing.applyReceivedFrames(connection, 91, &.{.{ .max_stream_data = .{ .stream_id = id.value, .maximum_stream_data = start + 1 } }}, null, .not_ect);
        const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromMilliseconds(5) });
        if (absolute)
            try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithDeadline(id, deadline))
        else
            try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithTimeout(id, .fromMilliseconds(5)));
        try std.testing.expect(fixture.client.session(id) == session);
        try std.testing.expectEqual(@as(usize, 2), fixture.client.sessionCount());
        try std.testing.expect(session.control.local_close_started and !session.control.local_close_sent);
        try std.testing.expectEqual(@as(usize, 1), session.close_state.fragment.wire_sent);
        try std.testing.expectEqual(start + 1, connection.sendStreamStats(id.value).?.highest_sent_offset);
        try fixture.queueDatagram(sibling, "still live");
        var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
        defer event.deinit(allocator);
        try std.testing.expectEqualStrings("still live", event.datagram.payload);
        try quic.one_rtt.testing.applyReceivedFrames(connection, 92, &.{.{ .max_stream_data = .{ .stream_id = id.value, .maximum_stream_data = start + 1024 } }}, null, .not_ect);
        try std.testing.expect(try fixture.client.removeSessionWithTimeout(id, .fromSeconds(1)));
        try std.testing.expectEqual(start + 9, connection.sendStreamStats(id.value).?.highest_sent_offset);
        try std.testing.expect(fixture.client.session(id) == null and fixture.client.session(sibling.session_id) == sibling);
        try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.recvStreamStats(id.value).?.stop_sending_sent.?.application_error_code);
        try expectPeerClose(&fixture, id.value, 0, "");
    }
}

test "WebTransport endpoint client removal deadline rejects invalid budgets before mutation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = session.session_id;
    const connection = &fixture.client.h3.established.connection;
    const packet_number = connection.next_packet_number;
    try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithTimeout(id, .zero));
    try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithTimeout(id, .fromMilliseconds(-1)));
    try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithDeadline(id, .{ .clock = .awake, .raw = .zero }));
    try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithDeadline(id, .{ .clock = .real, .raw = .fromNanoseconds(std.math.maxInt(i96)) }));
    try std.testing.expect(fixture.client.session(id) == session and !session.control.local_close_started);
    try std.testing.expect(session.close_state.pending == null);
    try std.testing.expectEqual(packet_number, connection.next_packet_number);
    try std.testing.expect(!try fixture.client.removeSessionWithTimeout(.init(4), .fromSeconds(1)));
}

const ExpiringSend = struct {
    delegate: std.Io,
    now_ns: i96 = 1_000_000,
    calls: usize = 0,
    expire_after: usize,

    fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        return .fromNanoseconds(self.now_ns);
    }

    fn send(context: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        const result = self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
        if (self.calls == self.expire_after and result[0] == null and result[1] != 0) self.now_ns += 2;
        return result;
    }
};

test "WebTransport endpoint client removal deadline spans CLOSE RESET and STOP without renewal" {
    for ([_]usize{ 1, 2, 3 }) |expire_after| {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = session.session_id;
        const bidi = try session.openBidirectionalStream(&fixture.client);
        const connection = &fixture.client.h3.established.connection;
        const before = connection.sendStreamStats(id.value).?.highest_sent_offset;
        const original_io = connection.endpoint.io;
        var observed = ExpiringSend{ .delegate = original_io, .expire_after = expire_after };
        var vtable = original_io.vtable.*;
        vtable.now = ExpiringSend.now;
        vtable.netSend = ExpiringSend.send;
        connection.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
        defer connection.endpoint.io = original_io;
        const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(observed.now_ns + 1) };
        try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithDeadline(id, deadline));
        try std.testing.expect(fixture.client.session(id) == session and session.control.local_close_sent);
        try std.testing.expectEqual(before + 9, connection.sendStreamStats(id.value).?.highest_sent_offset);
        try std.testing.expectEqual(expire_after >= 2, session.streams.get(bidi).?.send_reset != null);
        try std.testing.expectEqual(expire_after >= 3, session.streams.get(bidi).?.stop_sent != null);
        try std.testing.expect(connection.recvStreamStats(id.value).?.stop_sending_sent == null);
        try std.testing.expectEqual(expire_after, observed.calls);
        try std.testing.expect(try fixture.client.removeSessionWithDeadline(id, .{ .clock = .awake, .raw = .fromNanoseconds(observed.now_ns + std.time.ns_per_s) }));
        try std.testing.expectEqual(@as(usize, 4), observed.calls);
        try std.testing.expectEqual(before + 9, connection.sendStreamStats(id.value).?.highest_sent_offset);
        try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.sendStreamStats(bidi).?.reset.?.application_error_code);
        try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.recvStreamStats(bidi).?.stop_sending_sent.?.application_error_code);
        try std.testing.expect(fixture.client.session(sibling.session_id) == sibling);
    }
}

test "WebTransport endpoint client removal deadline resumes an explicit CLOSE metadata" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    _ = try fixture.addSession();
    const id = session.session_id;
    const connection = &fixture.client.h3.established.connection;
    const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, id.value);
    try std.testing.expectError(error.Timeout, session.closeWithTimeout(&fixture.client, 77, "preserved", .fromMilliseconds(5)));
    try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithTimeout(id, .fromMilliseconds(5)));
    try std.testing.expectEqual(@as(u32, 77), session.close_state.pending.?.code);
    const pending = try webtransport.Capsule.parse(session.close_state.pending.?.bytes());
    try std.testing.expectEqualStrings("preserved", pending.capsule.close_session.reason);
    try quic.one_rtt.testing.applyReceivedFrames(connection, 93, &.{.{ .max_stream_data = .{ .stream_id = id.value, .maximum_stream_data = start + 1024 } }}, null, .not_ect);
    try std.testing.expect(try fixture.client.removeSessionWithTimeout(id, .fromSeconds(1)));
    var expected: [64]u8 = undefined;
    const capsule = try control_mod.writeCloseInto(&expected, 77, "preserved");
    try std.testing.expectEqual(start + 2 + capsule.len, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try expectPeerClose(&fixture, id.value, 77, "preserved");
}

test "WebTransport endpoint client removal deadline bounds congestion waits and remains resumable" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = session.session_id;
    const connection = &fixture.client.h3.established.connection;
    const start = connection.sendStreamStats(id.value).?.highest_sent_offset;
    quic.one_rtt.testing.clampCongestionWindowToBytesInFlight(connection);
    try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithTimeout(id, .fromMilliseconds(5)));
    try std.testing.expect(fixture.client.session(id) == session and fixture.client.session(sibling.session_id) == sibling);
    try std.testing.expect(!session.control.local_close_sent and !session.control.local_close_failed);
    try std.testing.expectEqual(start, connection.sendStreamStats(id.value).?.highest_sent_offset);
    quic.one_rtt.testing.acknowledgeAllInFlight(connection);
    try std.testing.expect(try fixture.client.removeSessionWithTimeout(id, .fromSeconds(1)));
    try std.testing.expectEqual(start + 9, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try expectPeerClose(&fixture, id.value, 0, "");
    try std.testing.expect(!connection.closing());
}

test "WebTransport endpoint client removal deadline completes pending DRAIN before CLOSE" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = session.session_id;
    const connection = &fixture.client.h3.established.connection;
    const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, id.value);
    try quic.one_rtt.testing.applyReceivedFrames(connection, 94, &.{.{ .max_stream_data = .{ .stream_id = id.value, .maximum_stream_data = start + 1 } }}, null, .not_ect);
    try std.testing.expectError(error.Timeout, session.drainWithTimeout(&fixture.client, .fromMilliseconds(5)));
    try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithTimeout(id, .fromMilliseconds(5)));
    try std.testing.expect(session.drain_state.pending() and session.close_state.pending == null);
    try std.testing.expect(!session.control.local_close_started);
    try std.testing.expectEqual(start + 1, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try quic.one_rtt.testing.applyReceivedFrames(connection, 95, &.{.{ .max_stream_data = .{ .stream_id = id.value, .maximum_stream_data = start + 1024 } }}, null, .not_ect);
    try std.testing.expect(try fixture.client.removeSessionWithTimeout(id, .fromSeconds(1)));
    var buffer: [16]u8 = undefined;
    const drain = try control_mod.writeDrainInto(&buffer);
    try std.testing.expectEqual(start + 2 + drain.len + 9, connection.sendStreamStats(id.value).?.highest_sent_offset);
    var control = try control_mod.Control.init(allocator, id);
    defer control.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    var header_read = false;
    var draining = false;
    while (true) {
        const bytes = fixture.peer.availableReceivedStream(id.value) orelse &.{};
        if (!header_read and bytes.len != 0) {
            const frame = try http3.Frame.parse(bytes);
            try std.testing.expectEqual(http3.FrameType.headers, frame.frame_type);
            try fixture.peer.releaseReceivedCapacity(id.value, frame.consumed);
            header_read = true;
        }
        if (header_read) {
            if (try control.pollOnce(&fixture.peer)) |event| switch (event) {
                .draining => {
                    try std.testing.expect(!draining);
                    draining = true;
                    continue;
                },
                .closed => |closed| {
                    try std.testing.expect(draining);
                    try std.testing.expectEqual(@as(u32, 0), closed.code);
                    return;
                },
                else => return error.TestUnexpectedResult,
            };
        }
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(allocator);
    }
}

test "WebTransport endpoint client removal deadline keeps protocol rejection ahead of FIN" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = session.session_id;
    const connection = &fixture.client.h3.established.connection;
    const start = connection.sendStreamStats(id.value).?.highest_sent_offset;
    try fixture.close(session, &.{0xff});
    try fixture.expectClose(session);
    quic.one_rtt.testing.clampCongestionWindowToBytesInFlight(connection);
    try std.testing.expectError(error.Timeout, fixture.client.removeSessionWithTimeout(id, .fromMilliseconds(5)));
    try std.testing.expect(fixture.client.session(id) == session);
    try std.testing.expect(session.control.post_terminal_data_pending and !session.control.handledPostTerminalData());
    try std.testing.expectEqual(start, connection.sendStreamStats(id.value).?.highest_sent_offset);
    quic.one_rtt.testing.acknowledgeAllInFlight(connection);
    try std.testing.expect(try fixture.client.removeSessionWithTimeout(id, .fromSeconds(1)));
    try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, connection.sendStreamStats(id.value).?.reset.?.application_error_code);
    try std.testing.expectEqual(start, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try fixture.expectWireCancellation(id.value, true);
    try std.testing.expect(fixture.client.session(sibling.session_id) == sibling and !connection.closing());
}
