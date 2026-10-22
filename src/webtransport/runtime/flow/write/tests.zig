const std = @import("std");
const webtransport = @import("../../../mod.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
const stream = @import("../../stream.zig");
const ObservedBatchSend = @import("../../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

fn init(pair: *Pair, io: std.Io, data: u64) !void {
    var peer = webtransport.defaultSettings(.{});
    peer.webtransport_initial_max_data = data;
    try pair.initWithSettings(io, webtransport.defaultSettings(.{}), peer);
}

test "WebTransport send flow deadline reports exact prefix and resumes after automatic grant" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |slices| {
        var pair: Pair = undefined;
        try init(&pair, threaded.io(), 3);
        defer pair.deinit();
        const id = try pair.client.openBidirectionalStream();
        var committed: usize = 99;
        if (slices) {
            try std.testing.expectError(error.Timeout, pair.client.sendStreamSlicesWithTimeout(id, &.{ "ab", "cd", "ef" }, true, &committed, .fromMilliseconds(5)));
        } else {
            try std.testing.expectError(error.Timeout, pair.client.sendStreamWithTimeout(id, "abcdef", true, &committed, .fromMilliseconds(5)));
        }
        try std.testing.expectEqual(@as(usize, 3), committed);
        try std.testing.expectEqual(@as(u64, 3), pair.client.streams.flow.?.sent.data);
        try std.testing.expectEqual(@as(u64, 3), pair.client.streams.get(id).?.bytes_sent);
        try std.testing.expect(!pair.client.streams.get(id).?.local_fin);
        var out: [16]u8 = undefined;
        const first = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
        try std.testing.expect(first == .data and !first.data.fin);
        try std.testing.expectEqualStrings("abc", out[0..first.data.bytes]);
        try std.testing.expectEqual(@as(u64, 6), pair.server.streams.flow.?.receive_limit.data);
        if (slices) {
            try pair.client.sendStreamSlicesWithTimeout(id, &.{ "d", "ef" }, true, &committed, .fromSeconds(1));
        } else {
            try pair.client.sendStreamWithTimeout(id, "def", true, &committed, .fromSeconds(1));
        }
        try std.testing.expectEqual(@as(usize, 3), committed);
        var resumed: usize = 0;
        while (true) {
            const second = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
            try std.testing.expect(second == .data);
            try std.testing.expectEqualStrings("def"[resumed..][0..second.data.bytes], out[0..second.data.bytes]);
            resumed += second.data.bytes;
            if (second.data.fin) break;
        }
        try std.testing.expectEqual(@as(usize, 3), resumed);
        try std.testing.expectEqual(@as(u64, 6), pair.client.streams.flow.?.sent.data);
        try std.testing.expectEqual(@as(u64, 6), pair.server.streams.flow.?.received.data);
    }
}

test "WebTransport send flow zero data credit permits association FIN and waits for body grant" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try init(&pair, threaded.io(), 0);
    defer pair.deinit();
    const empty = try pair.client.openUnidirectionalStream();
    try pair.client.sendStream(empty, "", true);
    var out: [16]u8 = undefined;
    const eof = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
    try std.testing.expect(eof == .data and eof.data.fin and eof.data.bytes == 0);
    try std.testing.expectEqual(@as(u64, 0), pair.client.streams.flow.?.sent.data);
    const id = try pair.client.openBidirectionalStream();
    try std.testing.expectError(error.Timeout, pair.client.writeStreamWithTimeout(id, "x", .fromMilliseconds(5)));
    try std.testing.expect(pair.client.streams.get(id).?.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), pair.client.streams.get(id).?.bytes_sent);
    try pair.server.grantData(1);
    try std.testing.expectEqual(@as(usize, 1), try pair.client.writeStreamWithTimeout(id, "x", .fromSeconds(1)));
    try std.testing.expectEqual(@as(u64, 1), pair.client.streams.flow.?.sent.data);
}

test "WebTransport send flow server waits for client grant on a unidirectional stream" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var client_settings = webtransport.defaultSettings(.{});
    client_settings.webtransport_initial_max_data = 0;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), client_settings, webtransport.defaultSettings(.{}));
    defer pair.deinit();
    const id = try pair.server.openUnidirectionalStream();
    var committed: usize = 99;
    try std.testing.expectError(error.Timeout, pair.server.sendStreamWithTimeout(id, "abc", true, &committed, .fromMilliseconds(5)));
    try std.testing.expectEqual(@as(usize, 0), committed);
    try pair.client.grantData(3);
    try pair.server.sendStreamWithTimeout(id, "abc", true, &committed, .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 3), committed);
    try std.testing.expectEqual(@as(u64, 3), pair.server.streams.flow.?.sent.data);
    var out: [16]u8 = undefined;
    var received: usize = 0;
    const deadline = std.Io.Clock.Timestamp.fromNow(pair.connection(.client).endpoint.io, .{ .raw = .fromSeconds(1), .clock = .awake });
    while (true) {
        const event = try pair.client.readStreamWithDeadline(&out, deadline);
        try std.testing.expect(event == .data);
        try std.testing.expectEqualStrings("abc"[received..][0..event.data.bytes], out[0..event.data.bytes]);
        received += event.data.bytes;
        if (event.data.fin) break;
    }
    try std.testing.expectEqual(@as(usize, 3), received);
}

test "WebTransport send flow waiting for data grant retains DRAIN notification" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try init(&pair, threaded.io(), 0);
    defer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    try pair.server.grantData(4);
    try pair.server.drain();
    var committed: usize = 99;
    try pair.client.sendStreamWithTimeout(id, "data", true, &committed, .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 4), committed);
    // Both control packets might not share one receive, so retain one deadline
    // while waiting for the advisory event if the grant arrived first.
    try std.testing.expect(try pair.client.receiveSessionEventWithTimeout(.fromSeconds(1)) == .draining);
    try std.testing.expectEqual(@as(u64, 4), pair.client.streams.flow.?.sent.data);
}

test "WebTransport send flow rejects duplicate grant while waiting for data credit" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try init(&pair, threaded.io(), 0);
    defer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    var storage: [16]u8 = undefined;
    const duplicate = try (webtransport.Capsule{ .max_data = 0 }).writeInto(&storage);
    try pair.sendCapsules(.client, duplicate);
    var committed: usize = 99;
    try std.testing.expectError(error.FlowControlViolation, pair.client.sendStreamWithTimeout(id, "data", true, &committed, .fromSeconds(1)));
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(u64, 0), pair.client.streams.flow.?.sent.data);
    try std.testing.expect(!pair.client.streams.get(id).?.local_fin);
    const conn = pair.connection(.client);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.flow_control_error), conn.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expect(!conn.closing());
}

test "WebTransport send flow batch deadline waits for one shared byte budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try init(&pair, threaded.io(), 0);
    defer pair.deinit();
    const first = try pair.client.openBidirectionalStream();
    const second = try pair.client.openBidirectionalStream();
    try pair.client.setStreamPriority(second, 10);
    const writes = [_]@import("../../stream/batch.zig").Write{
        .{ .stream_id = first, .data = "aaaa" },
        .{ .stream_id = second, .data = "bbbb" },
    };
    var counts = [_]usize{ 99, 99 };
    try std.testing.expectError(error.Timeout, pair.client.writeStreamsWithTimeout(&writes, &counts, .fromMilliseconds(5)));
    try std.testing.expectEqualSlices(usize, &.{ 0, 0 }, &counts);
    try pair.server.grantData(5);
    const result = try pair.client.writeStreamsWithTimeout(&writes, &counts, .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 2), result.progressed);
    try std.testing.expectEqualSlices(usize, &.{ 1, 4 }, &counts);
    try std.testing.expectEqual(@as(u64, 5), pair.client.streams.flow.?.sent.data);
}

test "WebTransport send flow multi-packet socket failure reports only submitted credit" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try init(&pair, threaded.io(), 4096);
    defer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    const conn = pair.connection(.client);
    conn.endpoint.gso_send_enabled = false;
    _ = try stream.prepareOnce(conn, &pair.client.streams, pair.client.session_id, id);
    const original_io = conn.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_after_prefix = 1 };
    var vtable = original_io.vtable.*;
    vtable.netSend = ObservedBatchSend.netSend;
    conn.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
    defer conn.endpoint.io = original_io;
    var payload: [4096]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index % 251);
    var committed: usize = 99;
    try std.testing.expectError(error.NetworkDown, pair.client.sendStreamWithTimeout(id, &payload, true, &committed, .fromSeconds(1)));
    try std.testing.expect(observed.last_message_count > 1);
    try std.testing.expect(committed > 0 and committed < payload.len);
    try std.testing.expectEqual(@as(u64, committed), pair.client.streams.flow.?.sent.data);
    try std.testing.expectEqual(@as(u64, committed), pair.client.streams.get(id).?.bytes_sent);
    try std.testing.expect(!pair.client.streams.get(id).?.local_fin);
    observed.fail_after_prefix = null;
    const already_sent = committed;
    try pair.client.sendStreamWithTimeout(id, payload[already_sent..], true, &committed, .fromSeconds(1));
    try std.testing.expectEqual(payload.len - already_sent, committed);
    try std.testing.expectEqual(@as(u64, payload.len), pair.client.streams.flow.?.sent.data);
    var out: [2048]u8 = undefined;
    var received: usize = 0;
    while (true) {
        const event = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
        try std.testing.expect(event == .data);
        try std.testing.expectEqualSlices(u8, payload[received..][0..event.data.bytes], out[0..event.data.bytes]);
        received += event.data.bytes;
        if (event.data.fin) break;
    }
    try std.testing.expectEqual(payload.len, received);
}
