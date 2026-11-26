const std = @import("std");
const webtransport = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const receive = @import("../receive.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
const ObservedBatchSend = @import("../../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;
const runtime = @import("../../../runtime.zig");

fn registryWithCredit(credit: u64) !webtransport.StreamRegistry {
    var registry = try webtransport.StreamRegistry.init(std.testing.allocator, .init(0), .server, .{});
    errdefer registry.deinit();
    var settings = webtransport.defaultSettings(.{});
    settings.webtransport_initial_max_data = credit;
    try registry.configureFlow(settings, settings);
    return registry;
}

fn stats(highest: u64, final_size: ?u64) quic.one_rtt.RecvStreamStats {
    return .{
        .bytes_received = 0,
        .bytes_read = 0,
        .highest_received_offset = highest,
        .available_bytes = 0,
        .first_received_at_ns = null,
        .receive_limit = 1024,
        .receive_window_available = 1024,
        .final_size = final_size,
        .reset = if (final_size) |final| .{ .application_error_code = 0, .final_size = final } else null,
        .stop_sending_sent = null,
    };
}

test "WebTransport receive flow charges highest offsets across streams without overlap" {
    var registry = try registryWithCredit(12);
    defer registry.deinit();
    const first = try registry.registerPeer(4, .bidirectional);
    first.receive_header_len = 3;
    try receive.account(&registry, first, stats(8, null));
    try std.testing.expectEqual(@as(u64, 5), registry.flow.?.received.data);
    // Duplicate/reordered fragments cannot charge the same body again.
    try receive.account(&registry, first, stats(8, null));
    try receive.account(&registry, first, stats(5, null));
    try receive.account(&registry, first, stats(10, null));
    try std.testing.expectEqual(@as(u64, 7), registry.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 10), first.receive_accounted_offset);
    const second = try registry.registerPeer(8, .bidirectional);
    second.receive_header_len = 2;
    try receive.account(&registry, second, stats(7, null));
    try std.testing.expectEqual(@as(u64, 12), registry.flow.?.received.data);
    const previous = registry.flow.?.*;
    try std.testing.expectError(error.FlowControlViolation, receive.account(&registry, second, stats(8, null)));
    try std.testing.expectEqualDeep(previous, registry.flow.?.*);
    try std.testing.expectEqual(@as(u64, 7), second.receive_accounted_offset);
    try std.testing.expect(registry.flow_violation);
}

test "WebTransport receive flow reconciles reset final size and rolls back association" {
    var registry = try registryWithCredit(9);
    defer registry.deinit();
    const stream = try registry.registerPeer(4, .bidirectional);
    stream.receive_header_len = 2;
    try receive.account(&registry, stream, stats(3, null));
    receive.consume(&registry, stream, 1);
    try receive.account(&registry, stream, stats(3, 11));
    receive.consumeAbandoned(&registry, stream);
    receive.consumeAbandoned(&registry, stream);
    try std.testing.expectEqual(@as(u64, 9), registry.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 9), registry.flow.?.consumed_data);
    try receive.account(&registry, stream, stats(11, 11));
    try std.testing.expectEqual(@as(u64, 9), registry.flow.?.received.data);
    try std.testing.expectError(error.FlowControlViolation, receive.account(&registry, stream, stats(11, 10)));
    registry.removeLastPeer(4);
    try std.testing.expectEqual(@as(u64, 0), registry.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 0), registry.flow.?.consumed_data);
    try std.testing.expectEqual(@as(u64, 0), registry.flow.?.received.bidi);
    const retry = try registry.registerPeer(4, .bidirectional);
    retry.receive_header_len = 2;
    try receive.account(&registry, retry, stats(3, 11));
    try std.testing.expectEqual(@as(u64, 9), registry.flow.?.received.data);
}

test "WebTransport receive flow reset cannot truncate its association header" {
    var registry = try registryWithCredit(9);
    defer registry.deinit();
    const stream = try registry.registerPeer(4, .bidirectional);
    stream.receive_header_len = 3;
    try std.testing.expectError(error.FlowControlViolation, receive.account(&registry, stream, stats(0, 2)));
    try std.testing.expectEqual(@as(u64, 0), registry.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 0), stream.receive_accounted_offset);
}

test "WebTransport receive flow zero data credit still permits stream association" {
    var registry = try registryWithCredit(0);
    defer registry.deinit();
    const stream = try registry.registerPeer(2, .unidirectional);
    stream.receive_header_len = 3;
    try receive.account(&registry, stream, stats(3, null));
    try std.testing.expectEqual(@as(u64, 0), registry.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 3), stream.receive_accounted_offset);
    try std.testing.expectError(error.FlowControlViolation, receive.account(&registry, stream, stats(4, null)));
}

test "WebTransport receive flow excess body rejects CONNECT before delivering data" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var local = webtransport.defaultSettings(.{});
    local.webtransport_initial_max_data = 5;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), webtransport.defaultSettings(.{}), local);
    defer pair.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try webtransport.BidirectionalStreamHeader.write(&bytes, std.testing.allocator, .init(0));
    try bytes.appendSlice(std.testing.allocator, "123456");
    try pair.connection(.client).send(&.{.{ .stream = .{ .stream_id = 4, .data = bytes.items } }});
    var output: [16]u8 = undefined;
    try std.testing.expectError(error.FlowControlViolation, pair.server.readStreamWithTimeout(&output, .fromSeconds(1)));
    try std.testing.expectEqual(@as(u64, 0), pair.server.streams.flow.?.received.data);
    const conn = pair.connection(.server);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.flow_control_error), conn.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expect(!conn.closing());
}

test "WebTransport receive flow reset charges lost bytes before transport retirement" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var local = webtransport.defaultSettings(.{});
    local.webtransport_initial_max_data = 6;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), webtransport.defaultSettings(.{}), local);
    defer pair.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try webtransport.BidirectionalStreamHeader.write(&bytes, std.testing.allocator, .init(0));
    const header_len = bytes.items.len;
    try bytes.append(std.testing.allocator, 'x');
    try pair.connection(.client).send(&.{
        .{ .stream = .{ .stream_id = 4, .data = bytes.items } },
        .{ .reset_stream = .{ .stream_id = 4, .application_error_code = webtransport.applicationErrorCodeToHttp3(42), .final_size = header_len + 6 } },
    });
    var output: [16]u8 = undefined;
    const event = try pair.server.readStreamWithTimeout(&output, .fromSeconds(1));
    try std.testing.expect(event == .reset);
    try std.testing.expectEqual(@as(?u32, 42), event.reset.error_info.application_code);
    try std.testing.expectEqual(@as(u64, 6), pair.server.streams.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, header_len + 6), pair.server.streams.get(4).?.receive_accounted_offset);
    try std.testing.expect(!pair.server.streams.flow_violation);
}

test "WebTransport receive flow reverse direction carries no second header" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var local = webtransport.defaultSettings(.{});
    local.webtransport_initial_max_data = 4;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), local, webtransport.defaultSettings(.{}));
    defer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    try pair.client.sendStream(id, "x", false);
    var output: [16]u8 = undefined;
    _ = try pair.server.readStreamWithTimeout(&output, .fromSeconds(1));
    // Inject a noncompliant peer directly: the runtime sender now enforces
    // the same session credit and cannot legitimately produce this excess.
    try pair.connection(.server).send(&.{.{ .stream = .{ .stream_id = id, .data = "12345" } }});
    try std.testing.expectError(error.FlowControlViolation, pair.client.readStreamWithTimeout(&output, .fromSeconds(1)));
    try std.testing.expectEqual(@as(u64, 0), pair.client.streams.get(id).?.receive_header_len);
    try std.testing.expect(pair.client.streams.flow_violation);
}

test "WebTransport receive flow automatic grant retries after socket submission fails" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var local = webtransport.defaultSettings(.{});
    local.webtransport_initial_max_data = 6;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), webtransport.defaultSettings(.{}), local);
    defer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    try pair.client.sendStream(id, "123456", false);
    const conn = pair.connection(.server);
    const deadline = std.Io.Clock.Timestamp.fromNow(conn.endpoint.io, .{ .raw = .fromSeconds(1), .clock = .awake });
    while ((if (conn.recvStreamStats(id)) |value| value.highest_received_offset else 0) < 9) {
        try pair.receiveProgress(.server, deadline);
    }
    const original_io = conn.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    conn.endpoint.io = observed.io();
    defer conn.endpoint.io = original_io;
    var output: [16]u8 = undefined;
    const event = try pair.server.readStream(&output);
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(@as(usize, 6), event.data.bytes);
    try std.testing.expectEqualStrings("123456", output[0..event.data.bytes]);
    try std.testing.expectEqual(@as(u64, 6), pair.server.streams.flow.?.consumed_data);
    try std.testing.expectEqual(@as(u64, 6), pair.server.streams.flow.?.receive_limit.data);
    try std.testing.expectEqual(@as(?u64, 12), pair.server.streams.flow.?.automaticDataGrant());
    observed.fail_on_call = null;
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(std.testing.allocator, conn.endpoint);
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 12;
    try dispatcher.registerConnection(handle, conn);
    _ = dispatcher.timers.disarmConnection(handle);
    try std.testing.expect(dispatcher.nextTimerDeadline() == null);
    try pair.server.h3.bindDispatcher();
    // Borrow the owning pair's state for one shared-endpoint operation. The
    // operation changes scheduling only; the pair retains allocation ownership.
    var accepted = runtime.EndpointAcceptedSession{
        .handle = handle,
        .dispatcher = &dispatcher,
        .h3 = &pair.server.h3,
        .request = undefined,
        .session_id = pair.server.session_id,
        .streams = pair.server.streams,
        .control = pair.server.control,
    };
    try accepted.setStreamPriority(id, 7);
    try std.testing.expectEqual(@as(u64, 12), pair.server.streams.flow.?.receive_limit.data);
    const timer = dispatcher.nextTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, timer.connection_id);
    try std.testing.expectEqual(conn.nextTimerDeadline().?, timer.timer);
    while (pair.client.streams.flow.?.send_limit.data < 12) {
        try pair.receiveProgress(.client, deadline);
        try std.testing.expect((try pair.client.pollSessionEvent()) == null);
    }
    try std.testing.expectEqual(@as(u64, 12), pair.client.streams.flow.?.send_limit.data);
}
