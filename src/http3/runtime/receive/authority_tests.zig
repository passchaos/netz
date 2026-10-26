const std = @import("std");
const http3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const support = @import("test_support/message_pair.zig");

test "HTTP/3 authority rejection preserves QPACK and accepts normalized sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pair: support.For(false) = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const owner = pair.owner();
    owner.qpack_decode.deinit();
    owner.qpack_decode = runtime.QpackDecodeState.init(allocator, 256, 4096);
    owner.options.local_settings.qpack_max_table_capacity = 256;
    for (0..3) |_| _ = try pair.connection().openUnidirectionalStream();
    var instructions: std.ArrayList(u8) = .empty;
    defer instructions.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&instructions, allocator);
    try http3.Qpack.writeEncoderInstruction(&instructions, allocator, .{ .set_capacity = 256 });
    try http3.Qpack.writeEncoderInstruction(&instructions, allocator, .{ .insert_literal = .{ .name = "x-sync", .value = "preserved" } });
    try pair.send(&.{.{ .stream = .{ .stream_id = 2, .data = instructions.items } }});
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-sync", "preserved");
    for ([_]u62{ 0, 4 }) |id| {
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(allocator);
        try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
            .{ .name = ":method", .value = "GET" },                                      .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/authority" },                                 .{ .name = ":authority", .value = if (id == 0) "[invalid]" else "LocalHOST" },
            .{ .name = "host", .value = if (id == 0) "[invalid]" else "localhost:443" }, .{ .name = "x-sync", .value = "preserved" },
        }, table);
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
            var found = false;
            for (event.head.request.headers) |header| if (std.mem.eql(u8, header.name, "x-sync")) {
                try std.testing.expectEqualStrings("preserved", header.value);
                found = true;
            };
            try std.testing.expect(found);
        }
        try std.testing.expectEqual(@as(u64, 1), owner.qpack_decode.table.insert_count);
    }
}
