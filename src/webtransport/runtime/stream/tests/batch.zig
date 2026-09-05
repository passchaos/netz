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
        .{ .input_index = 0, .priority = 1, .byte_count = 10 },
        .{ .input_index = 1, .priority = 3, .byte_count = 11 },
        .{ .input_index = 2, .priority = 3, .byte_count = 12 },
        .{ .input_index = 3, .priority = 2, .byte_count = 13 },
        .{ .input_index = 4, .priority = 4, .byte_count = 14 },
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
