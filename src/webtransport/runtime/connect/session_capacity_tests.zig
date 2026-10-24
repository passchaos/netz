const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime = @import("../../runtime.zig");
const ClientFixture = @import("../endpoint_client/test_support.zig").Fixture;
const ServerFixture = @import("../endpoint_server/test_support.zig").Fixture;
const allocator = std.testing.allocator;

fn disableFlow(settings: *http3.Settings) void {
    settings.webtransport_initial_max_data = 0;
    settings.webtransport_initial_max_streams_bidi = 0;
    settings.webtransport_initial_max_streams_uni = 0;
}

test "WebTransport pooling requires negotiated flow before a second client CONNECT" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |local| {
        var fixture: ClientFixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        if (local) disableFlow(&fixture.client.h3.options.local_settings) else disableFlow(&fixture.client.h3.control.settings.peer);
        const first = try fixture.addSession();
        try std.testing.expect(first.streams.flow == null);
        const connection = &fixture.client.h3.established.connection;
        const before_packet = connection.next_packet_number;
        const before_stream = fixture.client.h3.next_stream_id;
        try std.testing.expectError(error.SessionLimitExceeded, fixture.client.openSessionAttemptWithTimeout(.{ .authority = "localhost" }, .fromMilliseconds(5)));
        try std.testing.expectEqual(before_packet, connection.next_packet_number);
        try std.testing.expectEqual(before_stream, fixture.client.h3.next_stream_id);
        try std.testing.expectEqual(@as(usize, 0), fixture.client.pending_open_cleanup.count());
        try std.testing.expect(!first.control.state.closed);
        try fixture.queueDatagram(first, "alive");
        var datagram = (try fixture.poll(first)) orelse return error.TestUnexpectedResult;
        defer datagram.deinit(allocator);
        try std.testing.expect(datagram == .datagram);
        try std.testing.expectEqualStrings("alive", datagram.datagram.payload);

        // Termination releases the protocol's simultaneous-session slot even
        // while the application retains this Session and its close metadata.
        try fixture.close(first, &.{});
        var closed = (try fixture.poll(first)) orelse return error.TestUnexpectedResult;
        defer closed.deinit(allocator);
        try std.testing.expect(closed == .session and closed.session == .closed);
        const reason = closed.session.closed.reason;
        try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{ .authority = "localhost" }, .fromMilliseconds(5)));
        try std.testing.expectEqual(before_stream + 4, fixture.client.h3.next_stream_id);
        try std.testing.expectEqual(@as(usize, 1), fixture.client.sessions.count());
        try std.testing.expectEqualStrings("done", reason);
        try std.testing.expect(first.control.state.closed);
    }
}

test "WebTransport pooling rejects an excessive server CONNECT without negotiated flow" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture: ServerFixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    disableFlow(&fixture.client.options.local_settings);
    disableFlow(&fixture.connectionSession().control.settings.peer);
    const first = try fixture.addSession();
    try std.testing.expect(first.streams.flow == null);
    const id = try fixture.client.startRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/excess",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport-h3" }},
    }, null);
    var buffer: [16]u8 = undefined;
    if (fixture.endpoint.receiveWithTimeout(&.{quic.Version.version_1.wireValue()}, .fromMilliseconds(5), &buffer)) |value| {
        var unexpected = value;
        unexpected.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.Timeout, err);
    const connection = &fixture.connectionSession().established.connection;
    try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, connection.sendStreamStats(id).?.reset.?.application_error_code);
    try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, connection.recvStreamStats(id).?.stop_sending_sent.?.application_error_code);
    var saw_reset = false;
    var saw_stop = false;
    const absolute = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (!saw_reset or !saw_stop) {
        var packet = try fixture.client.established.connection.receivePacketServicingTimersDeadline(absolute);
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .reset_stream => |reset| if (reset.stream_id == id) {
                try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, reset.application_error_code);
                saw_reset = true;
            },
            .reset_stream_at => |reset| if (reset.stream_id == id) {
                try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, reset.application_error_code);
                saw_reset = true;
            },
            .stop_sending => |stop| if (stop.stream_id == id) {
                try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, stop.application_error_code);
                saw_stop = true;
            },
            else => {},
        };
    }
    try std.testing.expectEqual(@as(usize, 1), fixture.endpoint.sessionCountForConnection(fixture.handle));
    try std.testing.expect(!first.control.state.closed);
    try std.testing.expect(!connection.closing());
    _ = try fixture.openPeerStream(first);
    try fixture.closePeer(first, "done", &.{});
    const replacement = try fixture.addSession();
    try std.testing.expectEqual(@as(usize, 2), fixture.endpoint.sessionCountForConnection(fixture.handle));
    try std.testing.expect(first.control.state.closed);
    try std.testing.expect(!replacement.control.state.closed);
    try std.testing.expectEqual(@as(?u32, 77), first.control.state.close_code);
}

test "WebTransport pooling retains a live slot until failed CONNECT cancellation reaches the wire" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture: ClientFixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    disableFlow(&fixture.client.h3.control.settings.peer);
    const h3 = &fixture.client.h3;
    const id = try h3.startRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/abandoned",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport-h3" }},
    }, null);
    try fixture.client.pending_open_cleanup.reserve(allocator);
    const connection = &h3.established.connection;
    const original_window = connection.congestion.congestion_window;
    connection.congestion.congestion_window = 0;
    fixture.client.pending_open_cleanup.abandon(h3, id, http3.ApplicationErrorCode.request_cancelled);
    try std.testing.expectEqual(@as(usize, 1), fixture.client.pending_open_cleanup.liveCount());
    const before_stream = h3.next_stream_id;
    const before_packet = connection.next_packet_number;
    try std.testing.expectError(error.SessionLimitExceeded, fixture.client.openSessionAttemptWithTimeout(.{ .authority = "localhost" }, .fromMilliseconds(5)));
    try std.testing.expectEqual(before_stream, h3.next_stream_id);
    try std.testing.expectEqual(before_packet, connection.next_packet_number);
    connection.congestion.congestion_window = original_window;
    try fixture.client.pending_open_cleanup.advance(h3);
    try std.testing.expectEqual(@as(usize, 0), fixture.client.pending_open_cleanup.liveCount());
    try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{ .authority = "localhost" }, .fromMilliseconds(5)));
    try std.testing.expectEqual(before_stream + 4, h3.next_stream_id);
}

test "WebTransport pooling releases peer capacity one after retaining client close metadata" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |flow_enabled| {
        var fixture: ClientFixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        fixture.client.h3.control.settings.peer.webtransport_max_sessions = 1;
        if (!flow_enabled) disableFlow(&fixture.client.h3.control.settings.peer);
        const first = try fixture.addSession();
        try fixture.close(first, &.{});
        var closed = (try fixture.poll(first)) orelse return error.TestUnexpectedResult;
        defer closed.deinit(allocator);
        try std.testing.expect(closed == .session and closed.session == .closed);
        const before = fixture.client.h3.next_stream_id;
        try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{ .authority = "localhost" }, .fromMilliseconds(5)));
        try std.testing.expectEqual(before + 4, fixture.client.h3.next_stream_id);
        try std.testing.expectEqual(@as(usize, 1), fixture.client.sessions.count());
        try std.testing.expectEqualStrings("done", closed.session.closed.reason);
        fixture.client.max_sessions = 1;
        try std.testing.expectError(error.SessionLimitExceeded, fixture.client.openSessionAttemptWithTimeout(.{ .authority = "localhost" }, .fromMilliseconds(5)));
        try std.testing.expectEqual(before + 4, fixture.client.h3.next_stream_id);
    }
}

test "WebTransport pooling releases server capacity one after retaining close metadata" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]?usize{ null, 2 }) |retained| {
        var fixture: ServerFixture = undefined;
        try fixture.initWithCapacity(threaded.io(), 1, retained);
        defer fixture.deinit();
        const first = try fixture.addSession();
        try fixture.closePeer(first, "retained", &.{});
        const second = try fixture.addSession();
        try std.testing.expectEqual(@as(usize, 2), fixture.endpoint.sessionCountForConnection(fixture.handle));
        try std.testing.expect(first.control.state.closed and !second.control.state.closed);
        try std.testing.expectEqual(@as(?u32, 77), first.control.state.close_code);
        try fixture.closePeer(second, "retained-too", &.{});
        fixture.endpoint.limits.max_retained_sessions_per_connection = 2;
        const id = try fixture.client.startRequest(.{
            .method = "CONNECT",
            .scheme = "https",
            .authority = "localhost",
            .path = "/memory-full",
            .headers = &.{.{ .name = ":protocol", .value = "webtransport-h3" }},
        }, null);
        var buffer: [16]u8 = undefined;
        if (fixture.endpoint.receiveWithTimeout(&.{quic.Version.version_1.wireValue()}, .fromMilliseconds(5), &buffer)) |value| {
            var unexpected = value;
            unexpected.deinit(allocator);
            return error.TestUnexpectedResult;
        } else |err| try std.testing.expectEqual(error.Timeout, err);
        try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, fixture.connectionSession().established.connection.sendStreamStats(id).?.reset.?.application_error_code);
        try std.testing.expectEqual(@as(usize, 2), fixture.endpoint.sessionCountForConnection(fixture.handle));
    }
}

test "WebTransport pooling validates the retained owner limit before bind or allocation" {
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidSessionState, runtime.HandshakeServer.bindForEndpoint(failing.allocator(), undefined, .{ .ip4 = .loopback(0) }, .{ .max_retained_sessions_per_connection = 0 }, .{ .handshake = .{ .local_connection_id = "invalid-retention" } }));
    try std.testing.expect(!failing.has_induced_failure);
}
