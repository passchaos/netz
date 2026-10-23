const std = @import("std");
const http3 = @import("../../../mod.zig");
const webtransport = @import("../../../../webtransport/mod.zig");
const Fixture = @import("../../../../webtransport/runtime/endpoint_client/test_support.zig").Fixture;
const control_sender = @import("../../control/send.zig");

fn start(fixture: *Fixture, io: std.Io) !void {
    try fixture.initWithSettings(io, try webtransport.settingsWithSessionCapacity(.{
        .qpack_max_table_capacity = 64,
        .qpack_blocked_streams = 1,
    }, 2));
    errdefer fixture.deinit();
    _ = try fixture.addSession();
    const h3 = &fixture.client.h3;
    try h3.qpack_encode.configurePeerLimits(64, 1);
    try std.testing.expect((try h3.qpack_encode.insertField("x-hold", "old")) != null);
    try control_sender.sendConnectionQpackEncoderInstructions(&h3.established.connection, &h3.critical_stream_send_scratch, &h3.qpack_encode, &h3.qpack_encoder_send, &h3.qpack_encoder_prefix_sent, h3.options);
    var owner: ?u62 = null;
    try std.testing.expectEqual(@as(u62, 4), try h3.startRequestOwned(.{
        .method = "CONNECT",
        .authority = "localhost",
        .path = "/qpack-cancel",
        .headers = &.{
            .{ .name = ":protocol", .value = "webtransport" },
            .{ .name = "x-hold", .value = "old" },
        },
    }, null, &owner));
    try std.testing.expect(h3.qpack_encode.hasPendingSections(4));
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        const bytes = fixture.peer.availableReceivedStream(4) orelse &.{};
        _ = http3.Frame.parse(bytes) catch |err| switch (err) {
            error.BufferTooShort => {
                var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
                packet.deinit(std.testing.allocator);
                continue;
            },
            else => return err,
        };
        var table = http3.Qpack.DynamicTable.init(std.testing.allocator, 64);
        defer table.deinit();
        try table.setCapacity(64);
        _ = try table.insert("x-hold", "old");
        var request = try http3.decodeRequestHeadWithDynamicTable(std.testing.allocator, bytes, h3.options.local_settings, table);
        defer request.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("/qpack-cancel", request.path);
        return;
    }
}

fn feedback(fixture: *Fixture, offset: *u64, instruction: http3.Qpack.DecoderInstruction) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    if (offset.* == 0) try http3.writeQpackDecoderStreamPrefix(&bytes, std.testing.allocator);
    try http3.Qpack.writeDecoderInstruction(&bytes, std.testing.allocator, instruction);
    try fixture.peer.send(&.{.{ .stream = .{ .stream_id = 11, .offset = offset.*, .data = bytes.items } }});
    offset.* += bytes.items.len;
    const connection = &fixture.client.h3.established.connection;
    var packet = try connection.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
    defer packet.deinit(std.testing.allocator);
    try fixture.client.h3.processDetachedResponsePacket(0, &packet);
}

test "HTTP/3 local request cancellation accepts a delayed QPACK Section Ack" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try start(&fixture, threaded.io());
    defer fixture.deinit();
    try fixture.client.h3.tryCancelRequest(4, http3.ApplicationErrorCode.request_cancelled);
    var offset: u64 = 0;
    try feedback(&fixture, &offset, .{ .section_acknowledgment = 4 });
    try std.testing.expect(!fixture.client.h3.qpack_encode.hasPendingSections(4));
    try std.testing.expectEqual(@as(u64, 1), fixture.client.h3.qpack_encode.known_received_count);
    try std.testing.expect(!fixture.client.session(.init(0)).?.control.state.closed);
}

test "HTTP/3 local request cancellation retains QPACK entries until peer cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try start(&fixture, threaded.io());
    defer fixture.deinit();
    var offset: u64 = 0;
    try feedback(&fixture, &offset, .{ .insert_count_increment = 1 });
    try fixture.client.h3.tryCancelRequest(4, http3.ApplicationErrorCode.request_cancelled);
    try std.testing.expect((try fixture.client.h3.qpack_encode.insertField("x-new", "new")) == null);
    try feedback(&fixture, &offset, .{ .stream_cancellation = 4 });
    try std.testing.expect((try fixture.client.h3.qpack_encode.insertField("x-new", "new")) != null);
}

test "HTTP/3 cancellation signals QPACK abandonment before response HEADERS" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try start(&fixture, threaded.io());
    defer fixture.deinit();
    const h3 = &fixture.client.h3;
    try std.testing.expectEqual(@as(usize, 0), h3.qpack_decode.table.capacity);
    try h3.tryCancelRequest(4, http3.ApplicationErrorCode.request_cancelled);
    const cancellation = try http3.Qpack.decodeDecoderInstruction(h3.qpack_decode.pendingDecoderInstructions());
    try std.testing.expect(cancellation.instruction == .stream_cancellation);
    try std.testing.expectEqual(@as(u64, 4), cancellation.instruction.stream_cancellation);
    try h3.flushResponsePacketFeedbackOnce();
    const sent_end = h3.qpack_decoder_send.next_offset;
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (fixture.peer.recvStreamStats(10)) |stats| stats.highest_received_offset else 0) < sent_end) {
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
    const wire = fixture.peer.availableReceivedStream(10).?;
    try std.testing.expectEqual(@as(u8, 3), wire[0]);
    const received = try http3.Qpack.decodeDecoderInstruction(wire[1..]);
    try std.testing.expect(received.instruction == .stream_cancellation);
    try std.testing.expectEqual(@as(u64, 4), received.instruction.stream_cancellation);
}

test "HTTP/3 request completion retains QPACK references for delayed peer acknowledgment" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try start(&fixture, threaded.io());
    defer fixture.deinit();
    try fixture.client.h3.sendRequestBody(4, &.{}, true);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try (http3.Response{ .status = 403, .extended_connect = true }).write(&encoded, std.testing.allocator);
    try fixture.peer.send(&.{.{ .stream = .{ .stream_id = 4, .data = encoded.items, .fin = true } }});
    var response = try fixture.client.h3.receiveResponseWithTimeout(4, .fromSeconds(1));
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 403), response.response.status);
    try std.testing.expect(fixture.client.h3.qpack_encode.hasPendingSections(4));
    var offset: u64 = 0;
    try feedback(&fixture, &offset, .{ .section_acknowledgment = 4 });
    try std.testing.expect(!fixture.client.h3.qpack_encode.hasPendingSections(4));
}

test "HTTP/3 QPACK feedback one-byte prefix remains retryable and preserves queued instructions" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const h3 = &fixture.client.h3;
    h3.options.max_stream_frame_data = 1;
    h3.options.max_frames_per_packet = 1;
    try h3.qpack_decode.recordStreamCancellation(4);
    const connection = &h3.established.connection;
    connection.congestion.congestion_window = 0;
    try std.testing.expectError(error.CongestionLimited, h3.flushResponsePacketFeedbackOnce());
    try std.testing.expect(!h3.qpack_decoder_prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), h3.qpack_decoder_send.next_offset);
    try std.testing.expectEqual(@as(usize, 1), h3.qpack_decode.pendingDecoderInstructions().len);
    connection.congestion.congestion_window = 64 * 1024;
    try h3.flushResponsePacketFeedbackOnce();
    try std.testing.expect(h3.qpack_decoder_prefix_sent);
    try std.testing.expectEqual(@as(u64, 1), h3.qpack_decoder_send.next_offset);
    try std.testing.expectEqual(@as(usize, 1), h3.qpack_decode.pendingDecoderInstructions().len);
    try h3.flushResponsePacketFeedbackOnce();
    try std.testing.expectEqual(@as(u64, 2), h3.qpack_decoder_send.next_offset);
    try std.testing.expectEqual(@as(usize, 0), h3.qpack_decode.pendingDecoderInstructions().len);
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (fixture.peer.recvStreamStats(10)) |stats| stats.highest_received_offset else 0) < 2) {
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
    try std.testing.expectEqualSlices(u8, "\x03\x44", fixture.peer.availableReceivedStream(10).?);
}
