const std = @import("std");
const http3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const pair_support = @import("test_support/message_pair.zig");
const allocator = std.testing.allocator;

test {
    _ = @import("authority_tests.zig");
}

test "HTTP/3 field value rejection preserves QPACK state and healthy request streams" {
    try exercise(false);
}

test "HTTP/3 field value rejection preserves QPACK state and healthy response streams" {
    try exercise(true);
}

fn exercise(comptime response: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pair: pair_support.For(response) = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const owner = pair.owner();
    owner.qpack_decode.deinit();
    owner.qpack_decode = runtime.QpackDecodeState.init(allocator, 256, 4096);
    owner.options.local_settings.qpack_max_table_capacity = 256;
    if (!response) for (0..3) |_| {
        _ = try pair.connection().openUnidirectionalStream();
    };
    var instructions: std.ArrayList(u8) = .empty;
    defer instructions.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&instructions, allocator);
    try http3.Qpack.writeEncoderInstruction(&instructions, allocator, .{ .set_capacity = 256 });
    try http3.Qpack.writeEncoderInstruction(&instructions, allocator, .{ .insert_literal = .{ .name = "x-sync", .value = "preserved" } });
    try pair.send(&.{.{ .stream = .{ .stream_id = if (response) 3 else 2, .data = instructions.items } }});
    try std.testing.expectEqual(@as(u64, 1), owner.qpack_decode.table.insert_count);
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-sync", "preserved");
    for ([_]u62{ 0, 4 }) |id| {
        var fields: std.ArrayList(http3.Qpack.HeaderField) = .empty;
        defer fields.deinit(allocator);
        if (response) try fields.append(allocator, .{ .name = ":status", .value = "200" }) else try fields.appendSlice(allocator, &.{
            .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/healthy" },
        });
        if (id == 0) try fields.append(allocator, .{ .name = "x-bad", .value = " trailing " });
        try fields.append(allocator, .{ .name = "x-sync", .value = "preserved" });
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(allocator);
        try http3.Qpack.encodeDynamicBlock(&block, allocator, fields.items, table);
        try std.testing.expect(block.items[0] != 0);
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, allocator);
        try pair.send(&.{.{ .stream = .{ .stream_id = id, .data = bytes.items, .fin = true } }});
        if (id == 0) {
            try std.testing.expectError(error.InvalidHeader, pair.poll(id));
            try std.testing.expect(!pair.connection().closing());
            try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, pair.connection().recvStreamStats(id).?.stop_sending_sent.?.application_error_code);
        } else {
            var event = (try pair.poll(id)) orelse return error.TestUnexpectedResult;
            defer event.deinit(allocator);
            try std.testing.expect(event == .head);
            const decoded = if (response) event.head.response.headers else event.head.request.headers;
            var found = false;
            for (decoded) |field| if (std.mem.eql(u8, field.name, "x-sync")) {
                try std.testing.expectEqualStrings("preserved", field.value);
                found = true;
            };
            try std.testing.expect(found);
        }
        try std.testing.expectEqual(@as(u64, 1), owner.qpack_decode.table.insert_count);
    }
}
