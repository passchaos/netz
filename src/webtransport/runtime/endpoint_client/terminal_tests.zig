const std = @import("std");
const client_mod = @import("../endpoint_client.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const session_control = @import("../session_control.zig");
const handshake_stream = @import("../stream.zig");
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

const Fixture = @import("test_support.zig").Fixture;

test "WebTransport endpoint client rejects coalesced data after CLOSE and preserves sibling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const closing = try fixture.addSession();
    const sibling = try fixture.addSession();
    try fixture.close(closing, &.{0xff});
    try fixture.expectClose(closing);
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(closing));
    try std.testing.expect(closing.control.handledPostTerminalData());
    try std.testing.expect(!closing.close_response_pending);
    try std.testing.expect(!closing.control.local_close_sent);
    try fixture.expectWireCancellation(closing.session_id.value, true);
    try fixture.queueDatagram(closing, "late");
    try fixture.queueDatagram(sibling, "sibling");
    try std.testing.expect((try fixture.poll(closing)) == null);
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expectEqualStrings("sibling", event.datagram.payload);
    _ = try sibling.openBidirectionalStream(&fixture.client);
}

test "WebTransport endpoint client retries post-CLOSE cancellation without replying FIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    try fixture.close(session, &.{0xff});
    try fixture.expectClose(session);
    const endpoint = fixture.client.h3.established.connection.endpoint;
    const original_io = endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    endpoint.io = observed.io();
    defer endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.poll(session));
    try std.testing.expect(!session.control.handledPostTerminalData());
    try std.testing.expect(session.close_response_pending);
    try std.testing.expect(!session.control.local_close_sent);
    observed.fail_on_call = null;
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try fixture.expectWireCancellation(session.session_id.value, true);
}

test "WebTransport endpoint client rejects late data after its close reply FIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    try fixture.close(session, &.{});
    try fixture.expectClose(session);
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expect(session.control.local_close_sent);
    try fixture.appendConnect(session, &.{0xff}, false);
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
    try fixture.expectWireCancellation(session.session_id.value, false);
    try std.testing.expect((try fixture.poll(session)) == null);
}

test "WebTransport endpoint client tears down associated streams after peer CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const stream_id = try session.openBidirectionalStream(&fixture.client);
    try quic.one_rtt.testing.applyReceivedFrames(&fixture.client.h3.established.connection, 20, &.{.{ .stream = .{
        .stream_id = stream_id,
        .data = "late",
    } }}, null, .not_ect);
    try fixture.queueDatagram(session, "late");
    try fixture.close(session, &.{});
    try fixture.expectClose(session);
    // One FIN, one RESET_STREAM, then one STOP_SENDING; no application data.
    for (0..4) |_| try std.testing.expect((try fixture.poll(session)) == null);
    const stream = session.streams.get(stream_id).?;
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.send_reset.?.http3_code);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.stop_sent.?.http3_code);
    try std.testing.expectError(error.InvalidSessionState, session.sendDatagram(&fixture.client, "late"));
}

test "WebTransport endpoint client removal rejects pending data before FIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = session.session_id;
    try fixture.close(session, &.{0xff});
    try fixture.expectClose(session);
    try std.testing.expect(try fixture.client.removeSession(id));
    try fixture.expectWireCancellation(id.value, true);
    try std.testing.expect(fixture.client.session(id) == null);
}

test "WebTransport endpoint client hides data and cleans streams after local CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const stream_id = try session.openBidirectionalStream(&fixture.client);
    try quic.one_rtt.testing.applyReceivedFrames(&fixture.client.h3.established.connection, 20, &.{.{ .stream = .{
        .stream_id = stream_id,
        .data = "late",
    } }}, null, .not_ect);
    try fixture.queueDatagram(session, "late");
    try session.close(&fixture.client, 81, "local done");
    for (0..3) |_| try std.testing.expect((try fixture.poll(session)) == null);
    const stream = session.streams.get(stream_id).?;
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.send_reset.?.http3_code);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.stop_sent.?.http3_code);
    try std.testing.expect(!session.control.terminal_reported);
    try std.testing.expect(session.control.local_close_sent);
}

test "WebTransport endpoint client defers paced cancellation while sibling progresses" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    try fixture.close(session, &.{0xff});
    try fixture.expectClose(session);
    const connection = &fixture.client.h3.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expect(session.close_response_pending);
    try std.testing.expect(!session.control.handledPostTerminalData());
    try fixture.queueDatagram(sibling, "sibling");
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expectEqualStrings("sibling", event.datagram.payload);
    connection.pacer.enabled = false;
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
    try fixture.expectWireCancellation(session.session_id.value, true);
}

test "WebTransport endpoint client cancels malformed capsules and preserves sibling" {
    const cases = [_]struct { bytes: []const u8, fin: bool = false }{
        // Invalid UTF-8, short CLOSE value, oversized CLOSE declaration,
        // nonempty DRAIN, truncated Capsule varint, and truncated H3 DATA.
        .{ .bytes = &.{ 0, 8, 0x68, 0x43, 5, 0, 0, 0, 77, 0xff } },
        .{ .bytes = &.{ 0, 3, 0x68, 0x43, 3 } },
        .{ .bytes = &.{ 0, 4, 0x68, 0x43, 0x44, 5 } },
        .{ .bytes = &.{ 0, 5, 0x80, 0, 0x78, 0xae, 1 } },
        .{ .bytes = &.{ 0, 1, 0x40 }, .fin = true },
        .{ .bytes = &.{ 0, 4, 0x68 }, .fin = true },
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (cases) |case| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        try fixture.appendConnect(session, case.bytes, case.fin);
        try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
        try std.testing.expect(session.control.capsule_error_rejected);
        try std.testing.expect(session.control.state.closed);
        try std.testing.expect(!session.close_response_pending);
        try std.testing.expect((try fixture.poll(session)) == null);
        try std.testing.expectError(error.InvalidSessionState, session.sendDatagram(&fixture.client, "late"));
        try fixture.expectWireCancellation(session.session_id.value, true);
        try fixture.queueDatagram(sibling, "sibling");
        var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .datagram);
        try std.testing.expectEqualStrings("sibling", event.datagram.payload);
        _ = try sibling.openBidirectionalStream(&fixture.client);
    }
}

test "WebTransport endpoint client retries malformed Capsule rejection after send failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    try fixture.appendConnect(session, &.{ 0, 3, 0x68, 0x43, 3 }, false);
    const endpoint = fixture.client.h3.established.connection.endpoint;
    const original_io = endpoint.io;
    const original_available = fixture.client.h3.established.connection.availableReceivedStream(session.session_id.value).?.len;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    endpoint.io = observed.io();
    defer endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, fixture.poll(session));
    try std.testing.expect(session.control.capsule_error_pending);
    try std.testing.expect(!session.control.capsule_error_rejected);
    try std.testing.expectEqual(original_available, fixture.client.h3.established.connection.availableReceivedStream(session.session_id.value).?.len);
    try std.testing.expectError(error.InvalidSessionState, session.openBidirectionalStream(&fixture.client));
    observed.fail_on_call = null;
    try std.testing.expectError(error.InvalidCapsule, fixture.poll(session));
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try fixture.expectWireCancellation(session.session_id.value, true);
}

test "WebTransport endpoint client removal resumes pending malformed Capsule rejection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = session.session_id;
    try fixture.appendConnect(session, &.{ 0, 3, 0x68, 0x43, 3 }, false);
    const connection = &fixture.client.h3.established.connection;
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try std.testing.expect((try fixture.poll(session)) == null);
    try std.testing.expect(session.control.capsule_error_pending);
    try std.testing.expectError(error.InvalidSessionState, session.sendDatagram(&fixture.client, "late"));
    connection.pacer.enabled = false;
    try std.testing.expect(try fixture.client.removeSession(id));
    try fixture.expectWireCancellation(id.value, true);
}
