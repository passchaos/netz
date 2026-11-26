const std = @import("std");
const native_protocol_io = @import("../../../../internal/testing/native_protocol_io.zig");
const NativeSendIo = @import("../../../../internal/testing/deadline_send_io.zig").Native;
const webtransport = @import("../../../mod.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
const stream = @import("../../stream.zig");
const batch = @import("../../stream/batch.zig");
const ObservedBatchSend = @import("../../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

fn init(pair: *Pair, io: std.Io, data: u64) !void {
    var peer = webtransport.defaultSettings(.{});
    peer.webtransport_initial_max_data = data;
    try pair.initWithSettings(io, webtransport.defaultSettings(.{}), peer);
}

fn expectBody(pair: *Pair, expected: []const u8) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(pair.connection(.server).endpoint.io, .{ .raw = .fromSeconds(1), .clock = .awake });
    var out: [16]u8 = undefined;
    var received: usize = 0;
    while (true) {
        const event = try pair.server.readStreamWithDeadline(&out, deadline);
        try std.testing.expect(event == .data);
        try std.testing.expect(received + event.data.bytes <= expected.len);
        try std.testing.expectEqualSlices(u8, expected[received..][0..event.data.bytes], out[0..event.data.bytes]);
        received += event.data.bytes;
        if (event.data.fin) break;
    }
    try std.testing.expectEqual(expected.len, received);
}

test "WebTransport send flow complete one-attempt sends preserve credit on failure" {
    try native_protocol_io.run(completeOneAttempt);
}

fn completeOneAttempt(io: std.Io) !void {
    var pair: Pair = undefined;
    try init(&pair, io, 4);
    defer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    const conn = pair.connection(.client);
    const original_io = conn.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    var sender: NativeSendIo = .{
        .backend = .init(std.testing.allocator, .{ .async_limit = .nothing }),
        .fixed_clock = false,
        .delegate_io = original_io,
        .send_context = &observed,
        .send_override = ObservedBatchSend.netSend,
    };
    defer sender.backend.deinit();
    conn.endpoint.io = sender.io();
    defer conn.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, stream.sendSlicesOnce(conn, &pair.client.streams, pair.client.session_id, id, &.{ "ab", "cd" }, false));
    try std.testing.expectEqual(@as(u64, 0), pair.client.streams.flow.?.sent.data);
    try std.testing.expectEqual(@as(u64, 0), pair.client.streams.get(id).?.bytes_sent);
    try std.testing.expect(!pair.client.streams.get(id).?.prefix_sent);
    observed.fail_on_call = null;
    try stream.sendSlicesOnce(conn, &pair.client.streams, pair.client.session_id, id, &.{ "ab", "cd" }, false);
    try std.testing.expectEqual(@as(u64, 4), pair.client.streams.flow.?.sent.data);
    const calls_before_blocked = observed.calls;
    try std.testing.expectError(error.FlowControlBlocked, stream.sendOnce(conn, &pair.client.streams, pair.client.session_id, id, "e", true));
    try std.testing.expectEqual(calls_before_blocked, observed.calls);
    try std.testing.expect(!pair.client.streams.get(id).?.local_fin);
    try stream.finishOnce(conn, &pair.client.streams, pair.client.session_id, id);
    try std.testing.expectEqual(@as(u64, 4), pair.client.streams.flow.?.sent.data);
    try expectBody(&pair, "abcd");
}

test "WebTransport send flow fair one-attempt writes clamp scatter and contiguous bodies" {
    try native_protocol_io.run(fairOneAttempt);
}

fn fairOneAttempt(io: std.Io) !void {
    for ([_]bool{ false, true }) |slices| {
        var pair: Pair = undefined;
        try init(&pair, io, 4);
        defer pair.deinit();
        const id = try pair.client.openUnidirectionalStream();
        const conn = pair.connection(.client);
        const count = if (slices)
            try stream.writeSlicesOnce(conn, &pair.client.streams, pair.client.session_id, id, &.{ "ab", "cdef", "gh" })
        else
            try stream.writeOnce(conn, &pair.client.streams, pair.client.session_id, id, "abcdefgh");
        try std.testing.expectEqual(@as(usize, 4), count);
        try std.testing.expectEqual(@as(u64, 4), pair.client.streams.flow.?.sent.data);
        try std.testing.expectEqual(@as(u64, 4), pair.client.streams.get(id).?.bytes_sent);
        if (slices) {
            try std.testing.expectError(error.FlowControlBlocked, stream.writeSlicesOnce(conn, &pair.client.streams, pair.client.session_id, id, &.{ "ef", "gh" }));
        } else {
            try std.testing.expectError(error.FlowControlBlocked, stream.writeOnce(conn, &pair.client.streams, pair.client.session_id, id, "efgh"));
        }
        try stream.finishOnce(conn, &pair.client.streams, pair.client.session_id, id);
        try expectBody(&pair, "abcd");
    }
}

test "WebTransport send flow cross-stream partial batch commits one shared budget" {
    try native_protocol_io.run(crossStreamBatch);
}

fn crossStreamBatch(io: std.Io) !void {
    var pair: Pair = undefined;
    try init(&pair, io, 5);
    defer pair.deinit();
    const first = try pair.client.openBidirectionalStream();
    const second = try pair.client.openBidirectionalStream();
    const conn = pair.connection(.client);
    // The injector accepts one OS message. Keep each QUIC packet in its own
    // message so that accepting one cannot include a GSO group of two packets.
    conn.endpoint.gso_send_enabled = false;
    _ = try stream.prepareOnce(conn, &pair.client.streams, pair.client.session_id, first);
    _ = try stream.prepareOnce(conn, &pair.client.streams, pair.client.session_id, second);
    try pair.client.setStreamPriority(second, 10);
    const original_io = conn.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_after_prefix = 1 };
    var sender: NativeSendIo = .{
        .backend = .init(std.testing.allocator, .{ .async_limit = .nothing }),
        .fixed_clock = false,
        .delegate_io = original_io,
        .send_context = &observed,
        .send_override = ObservedBatchSend.netSend,
    };
    defer sender.backend.deinit();
    conn.endpoint.io = sender.io();
    defer conn.endpoint.io = original_io;
    const writes = [_]batch.Write{
        .{ .stream_id = first, .data = "aaaa" },
        .{ .stream_id = second, .data = "bbbb" },
    };
    var counts = [_]usize{ 99, 99 };
    const partial = try batch.writeOnce(conn, &pair.client.streams, pair.client.session_id, &writes, &counts);
    try std.testing.expectEqual(@as(usize, 1), partial.progressed);
    try std.testing.expectEqual(error.NetworkDown, partial.send_error.?);
    try std.testing.expectEqualSlices(usize, &.{ 0, 4 }, &counts);
    try std.testing.expectEqual(@as(u64, 4), pair.client.streams.flow.?.sent.data);
    observed.fail_after_prefix = null;
    try std.testing.expectEqual(@as(usize, 1), try stream.writeOnce(conn, &pair.client.streams, pair.client.session_id, first, "aaaa"));
    try std.testing.expectEqual(@as(u64, 5), pair.client.streams.flow.?.sent.data);
    try std.testing.expectEqual(@as(u64, 1), pair.client.streams.get(first).?.bytes_sent);
    try std.testing.expectEqual(@as(u64, 4), pair.client.streams.get(second).?.bytes_sent);
}
