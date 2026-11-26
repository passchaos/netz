const std = @import("std");
const webtransport = @import("../../../mod.zig");
const http3 = @import("../../../../http3/mod.zig");
const runtime = @import("../../../runtime.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
const ObservedBatchSend = @import("../../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

fn expectResponse(client: *http3.runtime.HandshakeClient, stream_id: u62, status: u16) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(client.established.connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        var event = (try client.receiveResponseEventWithDeadline(stream_id, deadline)) orelse continue;
        defer event.deinit(std.testing.allocator);
        if (event != .head) continue;
        try std.testing.expect(event.head == .response and event.head.response.status == status);
        return;
    }
}

test "WebTransport early DATAGRAM survives pre-CONNECT reordering and acceptance retry" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    const settings = webtransport.defaultSettings(.{});
    try pair.initWithSettingsAndEarlyDatagrams(threaded.io(), settings, settings, .{ .max_datagrams = 2, .max_bytes = 64 });
    defer pair.deinit();
    // The server sees an unknown future CONNECT ID while Session 0 remains
    // active. Only the connection-wide early queue owns those payloads.
    try pair.connection(.client).send(&.{
        .{ .datagram = .{ .data = "\x01oldest" } },
        .{ .datagram = .{ .data = "\x01early" } },
        .{ .datagram = .{ .data = "\x02sibling" } },
        .{ .datagram = .{ .data = "\x00barrier" } },
    });
    var barrier = try pair.server.receiveDatagramWithTimeout(.fromSeconds(1));
    defer barrier.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("barrier", barrier.datagram.payload);
    try std.testing.expectEqual(@as(usize, 1), pair.server.h3.connect_datagrams.early_datagrams.count(4));
    try std.testing.expectEqual(@as(usize, 1), pair.server.h3.connect_datagrams.early_datagrams.count(8));
    const id = try pair.client.h3.startRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/future",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport-h3" }},
    }, null);
    try std.testing.expectEqual(@as(u62, 4), id);
    var request = try pair.server.h3.receiveRequestEventWithTimeout(.fromSeconds(1));
    defer request.deinit(std.testing.allocator);
    try std.testing.expect(request == .message and request.message.stream_id == id);
    try pair.server.h3.ensureSettingsSent();
    const response = http3.Response{ .status = 200, .request_method = "CONNECT", .extended_connect = true };
    const connection = pair.connection(.server);
    const original_io = connection.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    connection.endpoint.io = observed.io();
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, pair.server.h3.tryAcceptConnectResponse(id, response));
    try std.testing.expect(!pair.server.h3.connect_datagrams.contains(id));
    try std.testing.expectEqual(@as(usize, 1), pair.server.h3.connect_datagrams.early_datagrams.count(id));
    connection.endpoint.io = original_io;
    try pair.server.h3.tryAcceptConnectResponse(id, response);
    try expectResponse(&pair.client.h3, id, 200);
    var datagram = (try pair.server.h3.pollConnectDatagram(id)) orelse return error.TestUnexpectedResult;
    defer datagram.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("early", datagram.payload);
    try std.testing.expectEqual(@as(usize, 1), pair.server.h3.connect_datagrams.early_datagrams.count(8));
    try pair.client.sendDatagram("alive");
    var alive = try pair.server.receiveDatagramWithTimeout(.fromSeconds(1));
    defer alive.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("alive", alive.datagram.payload);
}

test "WebTransport early DATAGRAM rejection discards only its CONNECT and ignores late payloads" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    const settings = webtransport.defaultSettings(.{});
    try pair.initWithSettingsAndEarlyDatagrams(threaded.io(), settings, settings, .{ .max_datagrams = 4, .max_bytes = 64 });
    defer pair.deinit();
    try pair.connection(.client).send(&.{
        .{ .datagram = .{ .data = "\x01denied" } },
        .{ .datagram = .{ .data = "\x02sibling" } },
        .{ .datagram = .{ .data = "\x00barrier" } },
    });
    var barrier = try pair.server.receiveDatagramWithTimeout(.fromSeconds(1));
    defer barrier.deinit(std.testing.allocator);
    const id = try pair.client.h3.startRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/denied",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport-h3" }},
    }, null);
    var pending = try runtime.HandshakeServer.receiveSessionRequestFromSessionWithTimeout(&pair.server.h3, .{}, .fromSeconds(1));
    var pending_live = true;
    defer if (pending_live) pending.deinit();
    var rejected = try pending.reject(403, &.{});
    pending_live = false;
    var rejected_live = true;
    defer if (rejected_live) rejected.deinit();
    try std.testing.expectEqual(@as(usize, 0), rejected.h3.connect_datagrams.early_datagrams.count(id));
    try std.testing.expectEqual(@as(usize, 1), rejected.h3.connect_datagrams.early_datagrams.count(8));
    try expectResponse(&pair.client.h3, id, 403);
    rejected.deinit();
    rejected_live = false;
    try pair.connection(.client).send(&.{
        .{ .datagram = .{ .data = "\x01late" } },
        .{ .datagram = .{ .data = "\x00alive" } },
    });
    var alive = try pair.server.receiveDatagramWithTimeout(.fromSeconds(1));
    defer alive.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("alive", alive.datagram.payload);
    try std.testing.expectEqual(@as(usize, 0), pair.server.h3.connect_datagrams.early_datagrams.count(id));
    try std.testing.expectEqual(@as(usize, 1), pair.server.h3.connect_datagrams.early_datagrams.count(8));
    try std.testing.expect(!pair.connection(.server).closing());
}
