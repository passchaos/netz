const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const control = @import("../session_control.zig");
const client_mod = @import("../endpoint_client.zig");
const Fixture = @import("test_support.zig").Fixture;

const Operation = enum { reset, reliable, stop };

fn target(fixture: *Fixture, session: *client_mod.Session, operation: Operation) !u62 {
    const connection = &fixture.client.h3.established.connection;
    connection.config.reliable_reset = .{ .local = true, .peer = true };
    if (operation == .stop) {
        const id: u62 = 3;
        try quic.one_rtt.testing.applyReceivedFrames(connection, 91, &.{.{ .stream = .{ .stream_id = id, .data = "body" } }}, null, .not_ect);
        _ = try session.streams.registerPeer(id, .unidirectional);
        return id;
    }
    const id = try session.openBidirectionalStream(&fixture.client);
    try session.sendStream(&fixture.client, id, "prefix", false);
    return id;
}

fn cancel(fixture: *Fixture, session: *client_mod.Session, id: u62, operation: Operation) !void {
    switch (operation) {
        .reset => try session.resetStreamWithTimeout(&fixture.client, id, 71, .fromSeconds(1)),
        .reliable => try session.resetStreamReliablyWithTimeout(&fixture.client, id, 71, 3, .fromSeconds(1)),
        .stop => try session.stopStreamWithTimeout(&fixture.client, id, 72, .fromSeconds(1)),
    }
}

test "WebTransport shared cancellation observes peer connection close across every Session" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const first = try fixture.addSession();
        const second = try fixture.addSession();
        const id = try target(&fixture, first, operation);
        try fixture.queueDatagram(first, "first");
        try fixture.queueDatagram(second, "second");
        try fixture.peer.closeApplication(99, "all sessions");
        const connection = &fixture.client.h3.established.connection;
        connection.congestion.congestion_window = 0;
        try std.testing.expectError(error.ConnectionClosed, cancel(&fixture, first, id, operation));
        // Inspect without another client call: the cancellation itself must
        // publish shared-connection termination and discard all queued data.
        for ([_]*client_mod.Session{ first, second }) |session| {
            try std.testing.expect(session.control.connection_terminated);
            try std.testing.expect(session.control.state.closed);
            try std.testing.expectEqual(@as(usize, 0), try fixture.client.h3.connect_datagrams.queuedCount(session.session_id.value));
        }
        const before = connection.next_packet_number;
        try std.testing.expect(first.streams.get(id).?.send_reset == null);
        try std.testing.expect(first.streams.get(id).?.stop_sent == null);
        try std.testing.expectError(error.ConnectionClosed, second.sendDatagram(&fixture.client, "late"));
        try std.testing.expectEqual(before, connection.next_packet_number);
        const close = connection.peerCloseInfo().?;
        try std.testing.expect(close == .application);
        try std.testing.expectEqual(@as(u64, 99), close.application.error_code);
        try std.testing.expectEqualStrings("all sessions", close.application.reason_phrase);
    }
}

test "WebTransport shared cancellation preserves Session CLOSE and sibling usability" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const first = try fixture.addSession();
        const second = try fixture.addSession();
        const id = try target(&fixture, first, operation);
        try fixture.queueDatagram(second, "sibling");
        var capsule_storage: [64]u8 = undefined;
        const capsule = try control.writeCloseInto(&capsule_storage, 77, "done");
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(std.testing.allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = capsule, .consumed = 0 }).write(&encoded, std.testing.allocator);
        const connection = &fixture.client.h3.established.connection;
        const offset = connection.recvStreamStats(first.session_id.value).?.highest_received_offset;
        try fixture.peer.send(&.{.{ .stream = .{ .stream_id = first.session_id.value, .offset = offset, .data = encoded.items } }});
        const window = connection.congestion.congestion_window;
        connection.congestion.congestion_window = 0;
        try std.testing.expectError(error.InvalidSessionState, cancel(&fixture, first, id, operation));
        connection.congestion.congestion_window = window;
        try std.testing.expect(first.control.pending_closed);
        try std.testing.expect(!second.control.state.closed and !connection.draining());
        try std.testing.expect(first.streams.get(id).?.send_reset == null);
        try std.testing.expect(first.streams.get(id).?.stop_sent == null);
        var ready = (try fixture.poll(first)) orelse return error.TestUnexpectedResult;
        defer ready.deinit(std.testing.allocator);
        try std.testing.expect(ready == .session and ready.session == .closed);
        try std.testing.expectEqual(@as(u32, 77), ready.session.closed.code);
        try std.testing.expectEqualStrings("done", ready.session.closed.reason);
        var sibling = (try fixture.poll(second)) orelse return error.TestUnexpectedResult;
        defer sibling.deinit(std.testing.allocator);
        try std.testing.expect(sibling == .datagram);
        try std.testing.expectEqualStrings("sibling", sibling.datagram.payload);
        _ = try second.openBidirectionalStream(&fixture.client);
    }
}

test "WebTransport shared cancellation publishes connection protocol failure to sibling Sessions" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    const id = try target(&fixture, first, .reliable);
    try fixture.queueDatagram(second, "discarded");
    const connection = &fixture.client.h3.established.connection;
    // DATA is prohibited on the HTTP/3 control stream. This connection-scoped
    // failure is processed while cancellation waits on a detached CONNECT.
    try fixture.peer.send(&.{.{ .stream = .{ .stream_id = 3, .data = "\x00\x00\x00" } }});
    connection.congestion.congestion_window = 0;
    try std.testing.expectError(error.UnexpectedFrame, cancel(&fixture, first, id, .reliable));
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(http3.ApplicationErrorCode.frame_unexpected, quic.one_rtt.testing.localCloseInfo(connection).?.error_code);
    for ([_]*client_mod.Session{ first, second }) |session| {
        try std.testing.expect(session.control.connection_terminated and session.control.state.closed);
        try std.testing.expectEqual(@as(usize, 0), try fixture.client.h3.connect_datagrams.queuedCount(session.session_id.value));
    }
    try std.testing.expect(first.streams.get(id).?.send_reset == null);
}

test "WebTransport shared cancellation preserves dispatcher and callback receive ownership" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const id = try target(&fixture, session, operation);
        const connection = &fixture.client.h3.established.connection;
        const before = connection.next_packet_number;
        fixture.client.h3.dispatcher_bound = true;
        try std.testing.expectError(error.InvalidDispatcherState, cancel(&fixture, session, id, operation));
        fixture.client.h3.dispatcher_bound = false;
        fixture.client.h3.callback_reader_active = true;
        try std.testing.expectError(error.ConcurrentRead, cancel(&fixture, session, id, operation));
        fixture.client.h3.callback_reader_active = false;
        try std.testing.expectEqual(before, connection.next_packet_number);
        try std.testing.expect(session.streams.get(id).?.send_reset == null);
        try std.testing.expect(session.streams.get(id).?.stop_sent == null);
        try cancel(&fixture, session, id, operation);
    }
}
