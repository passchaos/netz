const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const session_control = @import("../session_control.zig");
const quic = @import("../../../quic/mod.zig");
const Fixture = @import("test_support.zig").Fixture;
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

test "WebTransport endpoint client active removal closes CONNECT before releasing its owner" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = session.session_id;
    try std.testing.expect(try fixture.client.removeSession(id));
    const connection = &fixture.client.h3.established.connection;
    try std.testing.expect(connection.sendStreamStats(id.value).?.final_size != null or connection.sendStreamStats(id.value).?.reset != null);
    try std.testing.expect(connection.recvStreamStats(id.value).?.stop_sending_sent != null);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.recvStreamStats(id.value).?.stop_sending_sent.?.application_error_code);
    try std.testing.expect(fixture.client.session(id) == null);
    try std.testing.expect(fixture.client.session(sibling.session_id) == sibling);
    try std.testing.expect(!connection.closed());
}

test "WebTransport endpoint client active removal preserves its owner after CLOSE send failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    _ = try fixture.addSession();
    const id = session.session_id;
    const connection = &fixture.client.h3.established.connection;
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.client.removeSession(id));
    try std.testing.expect(fixture.client.session(id) == session);
    try std.testing.expectEqual(@as(usize, 2), fixture.client.sessionCount());
    try std.testing.expect(connection.sendStreamStats(id.value).?.final_size == null);
    try std.testing.expect(!connection.closed());
    connection.endpoint.io = original_io;
    try std.testing.expect(try fixture.client.removeSession(id));
    try std.testing.expect(fixture.client.session(id) == null);
}

fn expectPeerClose(fixture: *Fixture, stream_id: u62) !void {
    var control = try session_control.Control.init(std.testing.allocator, .init(stream_id));
    defer control.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(fixture.peer_endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    var header_read = false;
    while (true) {
        if (!header_read) {
            const data = fixture.peer.availableReceivedStream(stream_id) orelse &.{};
            if (data.len != 0) {
                const frame = try http3.Frame.parse(data);
                try std.testing.expectEqual(http3.FrameType.headers, frame.frame_type);
                try fixture.peer.releaseReceivedCapacity(stream_id, frame.consumed);
                header_read = true;
            }
        }
        if (header_read) {
            if (try control.pollOnce(&fixture.peer)) |event| {
                try std.testing.expect(event == .closed);
                try std.testing.expectEqual(@as(u32, 0), event.closed.code);
                try std.testing.expectEqualStrings("", event.closed.reason);
                return;
            }
        }
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        defer packet.deinit(std.testing.allocator);
    }
}

test "WebTransport endpoint client active removal resumes a one-byte DATA prefix without closing siblings" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = session.session_id;
    const connection = &fixture.client.h3.established.connection;
    const start = connection.sendStreamStats(id.value).?.highest_sent_offset;
    fixture.client.h3.options.max_frames_per_packet = 1;
    fixture.client.h3.options.max_stream_frame_data = 1;
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 3 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.client.removeSession(id));
    try std.testing.expect(fixture.client.session(id) == session and session.control.local_close_started);
    try std.testing.expectEqual(@as(usize, 2), session.close_state.fragment.wire_sent);
    try std.testing.expectEqual(@as(usize, 0), session.close_state.fragment.dataSent());
    try std.testing.expectEqual(start + 2, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try std.testing.expect(!connection.closed());
    connection.endpoint.io = original_io;
    try fixture.queueDatagram(session, "hidden");
    try std.testing.expect((try fixture.poll(session)) == null);
    try fixture.queueDatagram(sibling, "sibling");
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expectEqualStrings("sibling", event.datagram.payload);
    try std.testing.expect(try fixture.client.removeSession(id));
    try std.testing.expectEqual(start + 9, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try expectPeerClose(&fixture, id.value);
    try std.testing.expect(!connection.closed());
}

test "WebTransport endpoint client active removal does not replay CLOSE after cleanup send failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = session.session_id;
    const connection = &fixture.client.h3.established.connection;
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 2 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.client.removeSession(id));
    try std.testing.expect(fixture.client.session(id) == session and session.control.local_close_sent);
    const close_end = connection.sendStreamStats(id.value).?.highest_sent_offset;
    connection.endpoint.io = original_io;
    try fixture.queueDatagram(sibling, "alive");
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expect(try fixture.client.removeSession(id));
    try std.testing.expectEqual(close_end, connection.sendStreamStats(id.value).?.highest_sent_offset);
    try expectPeerClose(&fixture, id.value);
}

test "WebTransport endpoint client active removal pumps flow and congestion progress" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |flow| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = session.session_id;
        const connection = &fixture.client.h3.established.connection;
        const start = connection.sendStreamStats(id.value).?.highest_sent_offset;
        if (flow) _ = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, id.value) else quic.one_rtt.testing.clampCongestionWindowToBytesInFlight(connection);
        const Worker = struct {
            peer: *quic.one_rtt.Connection,
            stream_id: u62,
            limit: u64,
            request_end: u64,
            flow: bool,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.runFallible() catch |err| {
                    self.err = err;
                };
            }

            fn runFallible(self: *@This()) !void {
                const deadline = std.Io.Clock.Timestamp.fromNow(self.peer.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
                while ((if (self.peer.recvStreamStats(self.stream_id)) |stats| stats.highest_received_offset else 0) < self.request_end) {
                    var packet = try self.peer.receivePacketServicingTimersDeadline(deadline);
                    defer packet.deinit(std.testing.allocator);
                    _ = try self.peer.sendAckForPacketIfNeeded(packet.packet.packet_number, packet.frames);
                }
                if (self.flow) try self.peer.send(&.{.{ .max_stream_data = .{ .stream_id = self.stream_id, .maximum_stream_data = self.limit } }}) else _ = try self.peer.flushPendingAck();
            }
        };
        var worker = Worker{ .peer = &fixture.peer, .stream_id = id.value, .limit = start + 64, .request_end = start, .flow = flow };
        const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
        var joined = false;
        defer if (!joined) thread.join();
        const result = fixture.client.removeSession(id);
        thread.join();
        joined = true;
        if (worker.err) |err| return err;
        try std.testing.expect(try result);
        try std.testing.expect(!connection.closed());
        try std.testing.expect(fixture.client.session(sibling.session_id) == sibling);
        try expectPeerClose(&fixture, id.value);
    }
}

test "WebTransport endpoint client active removal handles peer CLOSE while waiting for credit" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |partial| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = session.session_id;
        const connection = &fixture.client.h3.established.connection;
        const start = try quic.one_rtt.testing.clampSendStreamLimitToUsed(connection, id.value);
        if (partial) {
            try fixture.peer.send(&.{.{ .max_stream_data = .{ .stream_id = id.value, .maximum_stream_data = start + 1 } }});
            while (connection.streamSendAvailable(id.value) == 0) try fixture.client.h3.receiveDetachedResponseProgress(id.value);
        }
        var storage: [64]u8 = undefined;
        const capsule = try session_control.writeCloseInto(&storage, 77, "peer done");
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(std.testing.allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = capsule, .consumed = 0 }).write(&wire, std.testing.allocator);
        const peer_offset = fixture.peer.sendStreamStats(id.value).?.highest_sent_offset;
        try fixture.peer.send(&.{.{ .stream = .{ .stream_id = id.value, .offset = peer_offset, .data = wire.items, .fin = true } }});
        try std.testing.expect(try fixture.client.removeSession(id));
        const stats = connection.sendStreamStats(id.value).?;
        if (partial) {
            try std.testing.expect(stats.reset != null);
            try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, stats.reset.?.application_error_code);
            try std.testing.expect(fixture.client.h3.outbound_bodies.find(id.value) == null);
        } else {
            try std.testing.expectEqual(@as(?u64, start), stats.final_size);
        }
        try std.testing.expect(fixture.client.session(sibling.session_id) == sibling);
        try std.testing.expect(!connection.closed());
    }
}

test "WebTransport endpoint client active removal terminates its registered stream" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = session.session_id;
    const stream_id = try session.openBidirectionalStream(&fixture.client);
    const connection = &fixture.client.h3.established.connection;
    try quic.one_rtt.testing.applyReceivedFrames(connection, 40, &.{.{ .stream = .{ .stream_id = stream_id, .data = "reverse" } }}, null, .not_ect);
    try std.testing.expect(try fixture.client.removeSession(id));
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.sendStreamStats(stream_id).?.reset.?.application_error_code);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, connection.recvStreamStats(stream_id).?.stop_sending_sent.?.application_error_code);
    try std.testing.expect(fixture.client.session(sibling.session_id) == sibling);
    try std.testing.expect(!connection.closed());
}

test "WebTransport endpoint client active removal applies forbidden CONNECT frame handling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = session.session_id;
    const connection = &fixture.client.h3.established.connection;
    const offset = connection.recvStreamStats(id.value).?.highest_received_offset;
    try quic.one_rtt.testing.applyReceivedFrames(connection, 90, &.{.{ .stream = .{ .stream_id = id.value, .offset = offset, .data = &.{ 1, 0 } } }}, null, .not_ect);
    try std.testing.expectError(error.UnexpectedFrame, fixture.client.removeSession(id));
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(http3.ApplicationErrorCode.frame_unexpected, quic.one_rtt.testing.localCloseInfo(connection).?.error_code);
    try std.testing.expect(fixture.client.session(id) == session);
    try std.testing.expect(try fixture.client.removeSession(id));
}
