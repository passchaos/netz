const std = @import("std");
const webtransport = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const association = @import("../../stream_association.zig");
const incremental = @import("../../stream_incremental.zig");

test "WebTransport stopped reliable reset settles credit and reports before missing prefix" {
    inline for (.{ false, true }) |server| {
        for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
            for ([_]bool{ false, true }) |reset_before_stop| {
                for ([_]bool{ false, true }) |single_attempt| {
                    try stoppedReset(server, direction, reset_before_stop, single_attempt);
                }
            }
        }
    }
}

fn stoppedReset(comptime server: bool, direction: webtransport.StreamDirection, reset_before_stop: bool, single_attempt: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb7} ** quic.protection.secret_len);
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-abandoned-recv",
        .peer_connection_id = "wt-abandoned-send",
        .local_endpoint = if (server) .server else .client,
        .initial_receive_max_data = 128,
        .initial_receive_max_stream_data = 128,
        .initial_receive_max_streams_bidi = 4,
        .initial_receive_max_streams_uni = 4,
        .reliable_reset = .{ .local = true },
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(allocator, session, if (server) .server else .client, .{});
    defer registry.deinit();
    var settings = webtransport.defaultSettings(.{});
    settings.webtransport_initial_max_data = 128;
    try registry.configureFlow(settings, settings);
    const id: u62 = (if (server) @as(u62, 0) else 1) + (if (direction == .bidirectional) @as(u62, 4) else 6);
    var prefix_storage: [16]u8 = undefined;
    var prefix_buffer = std.ArrayList(u8).initBuffer(&prefix_storage);
    const prefix = if (direction == .bidirectional)
        try webtransport.BidirectionalStreamHeader.writeInto(&prefix_storage, session)
    else blk: {
        try webtransport.UnidirectionalStreamHeader.writeWebTransport(&prefix_buffer, allocator, session);
        break :blk prefix_buffer.items;
    };
    var data: [18]u8 = undefined;
    @memcpy(data[0..prefix.len], prefix);
    @memcpy(data[prefix.len..][0..2], "ab");
    try quic.one_rtt.testing.applyReceivedFrames(&connection, 0, &.{.{ .stream = .{
        .stream_id = id,
        .data = data[0 .. prefix.len + 2],
    } }}, null, .not_ect);
    const final_size: u64 = @intCast(prefix.len + 10);
    const reliable_size: u64 = @intCast(prefix.len + 6);
    const reset: quic.Frame = .{ .reset_stream_at = .{
        .stream_id = id,
        .application_error_code = webtransport.applicationErrorCodeToHttp3(71),
        .final_size = final_size,
        .reliable_size = reliable_size,
    } };
    if (reset_before_stop) try quic.one_rtt.testing.applyReceivedFrames(&connection, 1, &.{reset}, null, .not_ect);
    var first_byte: [1]u8 = undefined;
    const first = (try incremental.poll(&connection, &registry, session, &first_byte)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data and first.data.bytes == 1);
    try std.testing.expectEqual(@as(u8, 'a'), first_byte[0]);
    try incremental.stop(&connection, &registry, id, 72);
    if (!reset_before_stop) try quic.one_rtt.testing.applyReceivedFrames(&connection, 1, &.{reset}, null, .not_ect);
    // STOP has already released QUIC credit, but its contiguous read cursor
    // cannot jump over the missing reliable bytes. The session must settle
    // every Final Size byte anyway and retain one reset event in its registry.
    try std.testing.expect(connection.recvStreamStats(id).?.bytes_read < reliable_size);
    const progressed = try association.drainAbandonedReceives(&connection, &registry, single_attempt);
    try std.testing.expectEqual(@as(u64, 10), registry.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 10), registry.flow.?.consumed_data);
    try std.testing.expect(progressed);
    try std.testing.expect(!try association.drainAbandonedReceives(&connection, &registry, single_attempt));

    @memcpy(data[prefix.len..][0..2], "ok");
    try quic.one_rtt.testing.applyReceivedFrames(&connection, 2, &.{.{ .stream = .{
        .stream_id = id + 4,
        .data = data[0 .. prefix.len + 2],
        .fin = true,
    } }}, null, .not_ect);
    var output: [8]u8 = undefined;
    const sibling = try incremental.readIdWithDeadline(&connection, &registry, session, id + 4, &output, .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }));
    try std.testing.expect(sibling == .data and sibling.data.fin);
    try std.testing.expectEqualStrings("ok", output[0..sibling.data.bytes]);
    const event = (try incremental.poll(&connection, &registry, session, &output)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .reset);
    try std.testing.expectEqual(id, event.reset.stream_id);
    try std.testing.expectEqual(final_size, event.reset.final_size);
    try std.testing.expectEqualDeep(webtransport.StreamError.fromHttp3(webtransport.applicationErrorCodeToHttp3(71)), event.reset.error_info);
    try std.testing.expect((try incremental.poll(&connection, &registry, session, &output)) == null);
    // Transport validation still owns the missing prefix. Its late delivery
    // must remain discarded without another application event or flow charge.
    try std.testing.expect(connection.recvStreamStats(id).?.bytes_read < reliable_size);
    try std.testing.expectError(error.FinalSizeMismatch, quic.one_rtt.testing.applyReceivedFrames(&connection, 3, &.{.{ .stream = .{
        .stream_id = id,
        .offset = final_size,
        .data = "invalid",
        .fin = true,
    } }}, null, .not_ect));
    try quic.one_rtt.testing.applyReceivedFrames(&connection, 4, &.{.{ .stream = .{
        .stream_id = id,
        .offset = @intCast(prefix.len + 2),
        .data = "cdefghij",
        .fin = true,
    } }}, null, .not_ect);
    try std.testing.expect((try incremental.poll(&connection, &registry, session, &output)) == null);
    try std.testing.expectEqual(@as(u64, 12), registry.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 12), registry.flow.?.consumed_data);
}
