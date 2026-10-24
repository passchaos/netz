const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const requests = @import("test_support/request_pair.zig");
const responses = @import("test_support/response_pair.zig");

test "HTTP/3 transferred request failure suspends its reader until cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: requests.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(std.testing.allocator);
    try requests.malformed(&invalid, &.{ .{ .name = ":path", .value = "/bad" }, .{ .name = ":scheme", .value = "https" } });
    var valid: std.ArrayList(u8) = .empty;
    defer valid.deinit(std.testing.allocator);
    try (http3.Request{ .method = "GET", .path = "/healthy", .authority = "localhost" }).write(&valid, std.testing.allocator);
    try pair.send(&.{ .{ .stream = .{ .stream_id = 0, .data = invalid.items } }, .{ .stream = .{ .stream_id = 4, .data = valid.items } } });
    var result = (try pair.server.pollRequestEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .failure and result.failure.err == error.MissingMethod);
    try std.testing.expectEqual(@as(u62, 0), result.failure.stream_id);
    try std.testing.expectEqual(@as(usize, 0), pair.server.pending_request_failures.count());
    try std.testing.expect((try pair.server.pollRequestEventForOnce(0)) == null);
    var sibling = (try pair.server.pollRequestEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer sibling.deinit(std.testing.allocator);
    try std.testing.expect(sibling == .event and sibling.event == .message and sibling.event.message.stream_id == 4);
    try std.testing.expect(sibling.event.message.value == .head);
    try std.testing.expect((try pair.server.readRequestDataOnce(0, &.{})) == null);
    try pair.server.tryCancelRequest(result.failure.stream_id, result.failure.application_error_code);
    try std.testing.expect(!pair.server.streaming_requests.contains(0));
    try std.testing.expect(pair.server.request_lifecycle.contains(4));
}

test "HTTP/3 transferred response failure suspends its reader until cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: responses.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(std.testing.allocator);
    try responses.missingStatus(&invalid);
    var valid: std.ArrayList(u8) = .empty;
    defer valid.deinit(std.testing.allocator);
    try (http3.Response{ .status = 204, .request_method = "GET" }).write(&valid, std.testing.allocator);
    try pair.send(&.{ .{ .stream = .{ .stream_id = 0, .data = invalid.items } }, .{ .stream = .{ .stream_id = 4, .data = valid.items, .fin = true } } });
    var result = (try pair.client.pollNextResponseEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result == .failure and result.failure.err == error.MissingStatus);
    try std.testing.expectEqual(@as(u62, 0), result.failure.stream_id);
    try std.testing.expectEqual(@as(usize, 0), pair.client.pending_response_failures.count());
    try std.testing.expect((try pair.client.pollResponseEventOnce(0)) == null);
    var sibling = (try pair.client.pollNextResponseEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer sibling.deinit(std.testing.allocator);
    try std.testing.expect(sibling == .event and sibling.event == .message and sibling.event.message.stream_id == 4);
    try std.testing.expect(sibling.event.message.value == .head);
    try std.testing.expect((try pair.client.readResponseDataOnce(0, &.{})) == null);
    try pair.client.tryCancelRequest(result.failure.stream_id, result.failure.application_error_code);
    try std.testing.expect(!pair.client.streaming_responses.contains(0));
    try std.testing.expect(pair.client.request_lifecycle.contains(4));
}

test "HTTP/3 completed request cancellation releases QUIC credit after reset acknowledgment" {
    inline for (.{ false, true }) |once| try cancellationCredit(once, false, false);
}

test "HTTP/3 incomplete request cancellation releases QUIC credit when late FIN arrives" {
    inline for (.{ false, true }) |once| try cancellationCredit(once, true, false);
}

test "HTTP/3 malformed request rejection returns QUIC credit without an admitted request" {
    inline for (.{ false, true }) |once| try cancellationCredit(once, false, true);
}

test "HTTP/3 malformed request caller cancellation keeps rejection owned after socket failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: requests.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try requests.malformed(&bytes, &.{ .{ .name = ":path", .value = "/bad" }, .{ .name = ":scheme", .value = "https" } });
    try pair.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items } }});
    const connection = &pair.server.established.connection;
    _ = try connection.tryFlushPendingAck();
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expectError(error.MissingMethod, pair.server.pollRequestEventOnce());
    try std.testing.expect(!pair.server.request_lifecycle.contains(0));
    connection.pacer.enabled = false;
    const original = pair.server_endpoint.io;
    const FailedSend = struct {
        fn send(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []std.Io.net.OutgoingMessage, _: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            return .{ error.SystemResources, 0 };
        }
    };
    {
        var vtable = original.vtable.*;
        vtable.netSend = FailedSend.send;
        pair.server_endpoint.io = .{ .userdata = original.userdata, .vtable = &vtable };
        defer pair.server_endpoint.io = original;
        try std.testing.expectError(error.SystemResources, pair.server.tryCancelRequest(0, http3.ApplicationErrorCode.message_error));
        try std.testing.expectEqual(@as(usize, 1), pair.server.pending_request_failures.count());
        try std.testing.expect(pair.server.streaming_requests.contains(0));
    }
    try std.testing.expectError(error.MissingMethod, pair.server.pollRequestEventOnce());
    try std.testing.expectEqual(@as(usize, 0), pair.server.pending_request_failures.count());
    try std.testing.expect(!pair.server.streaming_requests.contains(0));
    try std.testing.expect(!connection.closing());
}

fn cancellationCredit(comptime once: bool, late_fin: bool, malformed: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: requests.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    if (malformed) {
        try requests.malformed(&bytes, &.{ .{ .name = ":path", .value = "/bad" }, .{ .name = ":scheme", .value = "https" } });
    } else {
        try (http3.Request{ .method = "GET", .path = "/cancel", .authority = "localhost" }).write(&bytes, std.testing.allocator);
    }
    pair.server.established.connection.recv_max_streams_bidi = 1;
    pair.client.peer_max_streams_bidi = 1;
    try pair.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items, .fin = !late_fin } }});
    var head = (try pair.server.pollRequestEventOnceWithFailure()) orelse return error.TestUnexpectedResult;
    defer head.deinit(std.testing.allocator);
    if (malformed) {
        try std.testing.expect(head == .failure and head.failure.err == error.MissingMethod);
        try std.testing.expect(!pair.server.request_lifecycle.contains(0));
    } else {
        try std.testing.expect(head == .event and head.event == .message and head.event.message.value == .head);
    }
    const connection = &pair.server.established.connection;
    const limit_before = connection.recv_max_streams_bidi;
    if (once) try pair.server.tryCancelRequest(0, http3.ApplicationErrorCode.request_cancelled) else try pair.server.cancelRequest(0, http3.ApplicationErrorCode.request_cancelled);
    try std.testing.expectEqual(!late_fin, quic.one_rtt.testing.peerStreamReleaseRequested(connection, 0));
    if (late_fin) {
        try pair.send(&.{.{ .stream = .{ .stream_id = 0, .offset = bytes.items.len, .data = &.{}, .fin = true } }});
        try std.testing.expect(quic.one_rtt.testing.peerStreamReleaseRequested(connection, 0));
    }
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .raw = .fromSeconds(1), .clock = .awake });
    while (pair.client.streamResetReceived(0) == null or pair.client.streamStopped(0) == null) {
        var packet = try pair.client.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
    try pair.client.sendAck(0);
    while (!connection.peerStreamClosed(0)) try connection.servicePacketServicingTimersDeadline(deadline);
    try std.testing.expect(connection.peerStreamClosed(0));
    try std.testing.expectEqual(limit_before + 1, connection.recv_max_streams_bidi);
    try std.testing.expect(!pair.server.request_lifecycle.contains(0));
    while (pair.client.peer_max_streams_bidi != 2) {
        var packet = try pair.client.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
    // A peer constrained to one concurrent stream can issue its next
    // request after cancellation, rather than stalling at exhausted credit.
    bytes.clearRetainingCapacity();
    try (http3.Request{ .method = "GET", .path = "/next", .authority = "localhost" }).write(&bytes, std.testing.allocator);
    try pair.send(&.{.{ .stream = .{ .stream_id = 4, .data = bytes.items, .fin = true } }});
    var next = (try pair.server.pollRequestEventForOnce(4)) orelse return error.TestUnexpectedResult;
    defer next.deinit(std.testing.allocator);
    try std.testing.expect(next == .message and next.message.value == .head);
}
