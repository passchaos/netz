const std = @import("std");
const webtransport = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const batch = @import("../batch.zig");

test "WebTransport batch selects high priority streams with stable ties" {
    var registry = try webtransport.StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{},
    );
    defer registry.deinit();
    const low = (try registry.openLocal(.bidirectional)).stream_id;
    const high_first = (try registry.openLocal(.bidirectional)).stream_id;
    const high_second = (try registry.openLocal(.bidirectional)).stream_id;
    try registry.setPriority(low, -4);
    try registry.setPriority(high_first, 7);
    try registry.setPriority(high_second, 7);
    const writes = [_]batch.Write{
        .{ .stream_id = low, .data = "low" },
        .{ .stream_id = high_first, .data = "high-a" },
        .{ .stream_id = high_second, .data = "high-b" },
    };
    const epoch = registry.beginBatchEpoch();
    var selected: [3]usize = undefined;
    selected[0] = (try batch.testing.nextWrite(&registry, &writes, epoch)).?;
    try std.testing.expect(registry.markForBatch(
        writes[selected[0]].stream_id,
        epoch,
    ).?.first);
    selected[1] = (try batch.testing.nextWrite(&registry, &writes, epoch)).?;
    try std.testing.expect(registry.markForBatch(
        writes[selected[1]].stream_id,
        epoch,
    ).?.first);
    selected[2] = (try batch.testing.nextWrite(&registry, &writes, epoch)).?;
    try std.testing.expectEqualSlices(usize, &.{ 1, 2, 0 }, &selected);
}

test "WebTransport batch selection skips a marked high priority stream" {
    var registry = try webtransport.StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{},
    );
    defer registry.deinit();
    const high = (try registry.openLocal(.bidirectional)).stream_id;
    const low = (try registry.openLocal(.bidirectional)).stream_id;
    try registry.setPriority(high, 100);
    try registry.setPriority(low, -100);
    const writes = [_]batch.Write{
        .{ .stream_id = high, .data = "high" },
        .{ .stream_id = low, .data = "low" },
    };
    const epoch = registry.beginBatchEpoch();
    const first = (try batch.testing.nextWrite(&registry, &writes, epoch)).?;
    try std.testing.expectEqual(@as(usize, 0), first);
    try std.testing.expect(registry.markForBatch(high, epoch).?.first);
    try std.testing.expectEqual(
        @as(?usize, 1),
        try batch.testing.nextWrite(&registry, &writes, epoch),
    );
}

test "WebTransport steady batch keeps highest priorities with stable ties" {
    var selected: [3]batch.testing.Ordered = undefined;
    var count: usize = 0;
    for ([_]batch.testing.Ordered{
        .{ .input_index = 0, .priority = 1, .byte_count = 10, .send_offset = 20 },
        .{ .input_index = 1, .priority = 3, .byte_count = 11, .send_offset = 21 },
        .{ .input_index = 2, .priority = 3, .byte_count = 12, .send_offset = 22 },
        .{ .input_index = 3, .priority = 2, .byte_count = 13, .send_offset = 23 },
        .{ .input_index = 4, .priority = 4, .byte_count = 14, .send_offset = 24 },
    }) |candidate| {
        batch.testing.insertOrdered(
            &selected,
            &count,
            selected.len,
            candidate,
        );
    }
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 4, 1, 2 },
        &[_]usize{
            selected[0].input_index,
            selected[1].input_index,
            selected[2].input_index,
        },
    );
    try std.testing.expectEqual(@as(usize, 14), selected[0].byte_count);
    try std.testing.expectEqual(@as(u64, 24), selected[0].send_offset);
}

test "WebTransport steady batch stages offset without committing it" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x57} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-stage-client",
        .peer_connection_id = "wt-stage-server",
        .initial_send_max_streams_bidi = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    stream.prefix_sent = true;
    stream.send_offset = 123;
    const writes = [_]batch.Write{
        .{ .stream_id = stream.stream_id, .data = "payload" },
    };

    const staged = try batch.testing.stageSteady(
        &connection,
        &registry,
        &writes,
    );
    try std.testing.expectEqual(@as(usize, 1), staged.packet_count);
    try std.testing.expectEqual(
        @as(u64, stream.stream_id + 123 + 2 * "payload".len),
        staged.checksum,
    );
    try std.testing.expectEqual(@as(u64, 123), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
}

test "WebTransport batch validates duplicate beyond packet window" {
    const count = quic.one_rtt.max_batch_packets + 1;
    var registry = try webtransport.StreamRegistry.init(
        std.testing.allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = count },
    );
    defer registry.deinit();
    var writes: [count]batch.Write = undefined;
    for (&writes) |*item| {
        const stream = try registry.openLocal(.bidirectional);
        item.* = .{ .stream_id = stream.stream_id, .data = "x" };
    }
    writes[count - 1].stream_id = writes[0].stream_id;

    try std.testing.expectError(
        error.DuplicateStream,
        batch.validate(&registry, &writes),
    );
    for (registry.registered()) |stream| {
        try std.testing.expect(!stream.prefix_sent);
        try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
    }
}
