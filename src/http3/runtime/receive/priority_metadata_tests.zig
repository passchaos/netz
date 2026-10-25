//! Invalid scheduling hints leave authenticated message and QPACK state usable.
const std = @import("std");
const http3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const pair_support = @import("test_support/message_pair.zig");
const vectors = @import("../../../internal/priority/test_vectors.zig");
const allocator = std.testing.allocator;

test "HTTP/3 Priority metadata preserves protected requests responses and shared QPACK" {
    inline for ([_]bool{ false, true }) |response| {
        for (vectors.field_sections) |case| try exercise(response, case);
    }
}

fn exercise(comptime response: bool, case: vectors.FieldsCase) !void {
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
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-sync", "preserved");
    for ([_]u62{ 0, 4 }) |id| {
        var fields: std.ArrayList(http3.Qpack.HeaderField) = .empty;
        defer fields.deinit(allocator);
        if (response) try fields.append(allocator, .{ .name = ":status", .value = "200" }) else try fields.appendSlice(allocator, &.{
            .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/priority" },
        });
        if (id == 0) for (case.values) |value| try fields.append(allocator, .{ .name = "priority", .value = value });
        try fields.append(allocator, .{ .name = "x-sync", .value = "preserved" });
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(allocator);
        try http3.Qpack.encodeDynamicBlock(&block, allocator, fields.items, table);
        try std.testing.expect(block.items[0] != 0);
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, allocator);
        try pair.send(&.{.{ .stream = .{ .stream_id = id, .data = bytes.items, .fin = true } }});
        var event = (try pair.poll(id)) orelse return error.TestUnexpectedResult;
        defer event.deinit(allocator);
        try std.testing.expect(event == .head);
        const decoded = if (response) event.head.response.headers else event.head.request.headers;
        const priority = if (response) http3.Priority.parseFields(decoded) else owner.request_lifecycle.priority(id);
        try std.testing.expectEqual(@as(u3, if (id == 0) case.urgency else 3), priority.urgency);
        try std.testing.expectEqual(id == 0 and case.incremental, priority.incremental);
        var found = false;
        for (decoded) |field| if (std.mem.eql(u8, field.name, "x-sync")) {
            try std.testing.expectEqualStrings("preserved", field.value);
            found = true;
        };
        try std.testing.expect(found);
        try std.testing.expect(!pair.connection().closing());
        try std.testing.expect(pair.connection().recvStreamStats(id).?.stop_sending_sent == null);
        try std.testing.expectEqual(@as(u64, 1), owner.qpack_decode.table.insert_count);
    }
}
