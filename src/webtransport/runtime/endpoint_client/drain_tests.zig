const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const control_mod = @import("../session_control.zig");
const Fixture = @import("test_support.zig").Fixture;
const ObservedSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

fn receiveControl(fixture: *Fixture, control: *control_mod.Control) !control_mod.Event {
    const id = control.session_id.value;
    const deadline = std.Io.Clock.Timestamp.fromNow(fixture.peer_endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        if (fixture.peer.recvStreamStats(id)) |stats| {
            if (stats.bytes_read == 0) {
                const bytes = fixture.peer.availableReceivedStream(id) orelse &.{};
                if (bytes.len != 0) {
                    const frame = try http3.Frame.parse(bytes);
                    try std.testing.expectEqual(http3.FrameType.headers, frame.frame_type);
                    try fixture.peer.releaseReceivedCapacity(id, frame.consumed);
                }
            }
            if (try control.pollOnce(&fixture.peer)) |event| return event;
        }
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
}

test "WebTransport shared client DRAIN is advisory and reaches the peer once" {
    for ([_]bool{ false, true }) |tiny| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        fixture.peer.config.local_max_datagram_frame_size = 1200;
        if (tiny) fixture.client.h3.options.max_stream_frame_data = 1;
        const connection = &fixture.client.h3.established.connection;
        const start = connection.sendStreamStats(session.session_id.value).?.highest_sent_offset;
        try session.drain(&fixture.client);
        try std.testing.expect(session.control.local_drain_sent and session.control.state.draining);
        try std.testing.expect(!session.control.state.closed);
        try std.testing.expect(!session.drain_state.pending());
        try std.testing.expectEqual(start + 7, connection.sendStreamStats(session.session_id.value).?.highest_sent_offset);
        try std.testing.expect(connection.sendStreamStats(session.session_id.value).?.final_size == null);
        try session.drainWithTimeout(&fixture.client, .fromSeconds(1));
        try std.testing.expectEqual(start + 7, connection.sendStreamStats(session.session_id.value).?.highest_sent_offset);
        var control = try control_mod.Control.init(std.testing.allocator, session.session_id);
        defer control.deinit();
        try std.testing.expect((try receiveControl(&fixture, &control)) == .draining);
        try std.testing.expect((try control.pollOnce(&fixture.peer)) == null);
        const stream = try session.openBidirectionalStream(&fixture.client);
        try session.sendStream(&fixture.client, stream, "after-drain", true);
        try session.sendDatagram(&fixture.client, "after-drain");
        _ = try sibling.openBidirectionalStream(&fixture.client);
        try session.closeWithTimeout(&fixture.client, 77, "done", .fromSeconds(1));
        const closed = try receiveControl(&fixture, &control);
        try std.testing.expect(closed == .closed);
        try std.testing.expectEqual(@as(u32, 77), closed.closed.code);
        try std.testing.expectEqualStrings("done", closed.closed.reason);
    }
}

test "WebTransport shared client DRAIN deadline retains DATA prefix and sibling traffic" {
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
        const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromMilliseconds(5) });
        if (absolute) try std.testing.expectError(error.Timeout, session.drainWithDeadline(&fixture.client, deadline)) else try std.testing.expectError(error.Timeout, session.drainWithTimeout(&fixture.client, .fromMilliseconds(5)));
        try std.testing.expect(session.drain_state.pending() and session.control.local_drain_started);
        try std.testing.expect(!session.control.local_drain_sent and !session.control.local_close_failed);
        try std.testing.expectEqual(@as(usize, 1), session.drain_state.fragment.wire_sent);
        try std.testing.expectError(error.InvalidSessionState, session.close(&fixture.client, 77, "pending"));
        try std.testing.expectError(error.InvalidSessionState, session.sendDatagram(&fixture.client, "pending"));
        try fixture.queueDatagram(sibling, "sibling");
        var ready = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
        defer ready.deinit(std.testing.allocator);
        try std.testing.expect(ready == .datagram);
        try std.testing.expectEqualStrings("sibling", ready.datagram.payload);
        try quic.one_rtt.testing.applyReceivedFrames(connection, 92, &.{.{ .max_stream_data = .{ .stream_id = session.session_id.value, .maximum_stream_data = start + 1024 } }}, null, .not_ect);
        try session.drainWithTimeout(&fixture.client, .fromSeconds(1));
        try std.testing.expect(!session.drain_state.pending() and session.control.local_drain_sent);
        try std.testing.expectEqual(start + 7, connection.sendStreamStats(session.session_id.value).?.highest_sent_offset);
        try std.testing.expectEqual(@as(u64, 0), session.streams.flow.?.sent.data);
        var control = try control_mod.Control.init(std.testing.allocator, session.session_id);
        defer control.deinit();
        try std.testing.expect((try receiveControl(&fixture, &control)) == .draining);
        try std.testing.expect((try control.pollOnce(&fixture.peer)) == null);
    }
}

test "WebTransport shared client DRAIN socket failure resumes from call polling or removal" {
    const Resume = enum { call, poll, remove };
    for (std.enums.values(Resume)) |mode| {
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
        fixture.client.h3.options.max_stream_frame_data = 1;
        const original_io = connection.endpoint.io;
        var observed = ObservedSend{ .delegate = original_io, .fail_on_call = 3 };
        var vtable = original_io.vtable.*;
        vtable.netSend = ObservedSend.netSend;
        connection.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
        {
            defer connection.endpoint.io = original_io;
            try std.testing.expectError(error.NetworkDown, session.drain(&fixture.client));
        }
        try std.testing.expect(session.drain_state.pending() and !session.control.local_close_failed);
        try std.testing.expectEqual(@as(usize, 2), session.drain_state.fragment.wire_sent);
        switch (mode) {
            .call => try session.drain(&fixture.client),
            .poll => {
                for (0..16) |_| {
                    if (!session.drain_state.pending()) break;
                    const before = connection.next_packet_number;
                    try std.testing.expect((try fixture.poll(session)) == null);
                    try std.testing.expect(connection.next_packet_number <= before + 1);
                }
                try std.testing.expect(session.control.local_drain_sent and !session.drain_state.pending());
            },
            .remove => try std.testing.expect(try fixture.client.removeSession(id)),
        }
        var control = try control_mod.Control.init(std.testing.allocator, id);
        defer control.deinit();
        try std.testing.expect((try receiveControl(&fixture, &control)) == .draining);
        if (mode == .remove) {
            const closed = try receiveControl(&fixture, &control);
            try std.testing.expect(closed == .closed and closed.closed.code == 0);
        } else try std.testing.expectEqual(start + 7, connection.sendStreamStats(id.value).?.highest_sent_offset);
        _ = try sibling.openBidirectionalStream(&fixture.client);
    }
}

test "WebTransport shared client DRAIN validates deadlines and ownership before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    const before = connection.next_packet_number;
    try std.testing.expectError(error.Timeout, session.drainWithTimeout(&fixture.client, .zero));
    try std.testing.expectError(error.Timeout, session.drainWithDeadline(&fixture.client, .{ .clock = .awake, .raw = .zero }));
    var clone = session.*;
    try std.testing.expectError(error.InvalidSessionState, clone.drain(&fixture.client));
    fixture.client.h3.dispatcher_bound = true;
    try std.testing.expectError(error.InvalidDispatcherState, session.drainWithTimeout(&fixture.client, .fromSeconds(1)));
    fixture.client.h3.dispatcher_bound = false;
    fixture.client.h3.callback_reader_active = true;
    try std.testing.expectError(error.ConcurrentRead, session.drain(&fixture.client));
    fixture.client.h3.callback_reader_active = false;
    try std.testing.expectEqual(before, connection.next_packet_number);
    try std.testing.expect(!session.drain_state.pending() and !session.control.local_drain_started);
    try session.drain(&fixture.client);
}

test "WebTransport shared client DRAIN peer CLOSE abandons incomplete DATA and preserves event" {
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
        try std.testing.expectError(error.Timeout, session.drainWithTimeout(&fixture.client, .fromMilliseconds(5)));
        try fixture.close(session, &.{});
        try std.testing.expectError(error.InvalidSessionState, session.drainWithTimeout(&fixture.client, .fromSeconds(1)));
        try std.testing.expect(!session.drain_state.pending() and !session.control.local_drain_sent);
        const stats = connection.sendStreamStats(session.session_id.value).?;
        if (partial) {
            try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, stats.reset.?.application_error_code);
            try std.testing.expectEqual(start + 1, stats.highest_sent_offset);
        } else try std.testing.expectEqual(@as(?u64, start), stats.final_size);
        var closed = (try fixture.poll(session)) orelse return error.TestUnexpectedResult;
        defer closed.deinit(std.testing.allocator);
        try std.testing.expect(closed == .session and closed.session == .closed);
        try std.testing.expectEqual(@as(u32, 77), closed.session.closed.code);
        try std.testing.expectEqualStrings("done", closed.session.closed.reason);
        _ = try sibling.openBidirectionalStream(&fixture.client);
    }
}

test "WebTransport shared client DRAIN observes connection termination across all Sessions" {
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
    try std.testing.expectError(error.ConnectionClosed, session.drainWithTimeout(&fixture.client, .fromSeconds(1)));
    try std.testing.expect(!session.drain_state.pending());
    try std.testing.expect(session.control.connection_terminated and sibling.control.connection_terminated);
    try std.testing.expectEqual(@as(usize, 0), try fixture.client.h3.connect_datagrams.queuedCount(sibling.session_id.value));
}

test "WebTransport shared client DRAIN allocation failure retains unsubmitted wire state" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    const before = connection.next_packet_number;
    const start = connection.sendStreamStats(session.session_id.value).?.highest_sent_offset;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    {
        connection.endpoint.allocator = failing.allocator();
        defer connection.endpoint.allocator = std.testing.allocator;
        try std.testing.expectError(error.OutOfMemory, session.drain(&fixture.client));
    }
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(session.drain_state.pending() and session.control.local_drain_started);
    try std.testing.expectEqual(@as(usize, 0), session.drain_state.fragment.wire_sent);
    try std.testing.expectEqual(before, connection.next_packet_number);
    try std.testing.expectEqual(start, connection.sendStreamStats(session.session_id.value).?.highest_sent_offset);
    try session.drain(&fixture.client);
    var control = try control_mod.Control.init(std.testing.allocator, session.session_id);
    defer control.deinit();
    try std.testing.expect((try receiveControl(&fixture, &control)) == .draining);
}
