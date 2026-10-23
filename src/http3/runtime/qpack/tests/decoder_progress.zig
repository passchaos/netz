const std = @import("std");
const http3 = @import("../../../mod.zig");
const Decoder = @import("../state.zig").QpackDecodeState;

fn instructions() ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(std.testing.allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, std.testing.allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, std.testing.allocator, .{ .set_capacity = 256 });
    for ([_][]const u8{ "one", "two", "three" }) |value| {
        try http3.Qpack.writeEncoderInstruction(&bytes, std.testing.allocator, .{ .insert_literal = .{ .name = "x-progress", .value = value } });
    }
    return bytes.toOwnedSlice(std.testing.allocator);
}

fn incrementTotal(decoder: *Decoder) !u64 {
    var remaining = decoder.pendingDecoderInstructions();
    var total: u64 = 0;
    while (remaining.len != 0) {
        const instruction = try http3.Qpack.decodeDecoderInstruction(remaining);
        try std.testing.expect(instruction.instruction == .insert_count_increment);
        total += instruction.instruction.insert_count_increment;
        remaining = remaining[instruction.consumed..];
    }
    return total;
}

fn allocationFailure(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var decoder = Decoder.init(allocator, 256, 4096);
    defer decoder.deinit();
    var control = http3.ControlState{};
    decoder.applyEncoderStreamFrame(&control, .{ .stream_id = 6, .data = bytes }) catch |err| {
        try std.testing.expectEqual(decoder.table.insert_count, decoder.acknowledged_insert_count);
        try std.testing.expectEqual(decoder.table.insert_count, try incrementTotal(&decoder));
        return err;
    };
    try std.testing.expectEqual(@as(u64, 3), decoder.table.insert_count);
}

test "HTTP/3 QPACK decoder acknowledges committed inserts across every allocation failure" {
    const bytes = try instructions();
    defer std.testing.allocator.free(bytes);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailure, .{bytes});
}

test "HTTP/3 QPACK decoder resumes an OOM batch without losing or duplicating insert feedback" {
    const bytes = try instructions();
    defer std.testing.allocator.free(bytes);
    var recovered = false;
    for (0..64) |failure_point| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = failure_point });
        var decoder = Decoder.init(failing.allocator(), 256, 4096);
        defer decoder.deinit();
        var control = http3.ControlState{};
        const result = decoder.applyEncoderStreamFrame(&control, .{ .stream_id = 6, .data = bytes });
        if (result) |_| continue else |err| {
            if (err != error.OutOfMemory) return err;
            if (decoder.table.insert_count == 0) continue;
        }
        const committed = decoder.table.insert_count;
        try std.testing.expect(committed < 3);
        try std.testing.expectEqual(committed, try incrementTotal(&decoder));
        decoder.clearDecoderInstructions();
        failing.fail_index = std.math.maxInt(usize);
        try decoder.applyEncoderStreamFrame(&control, .{ .stream_id = 6, .offset = bytes.len, .data = &.{} });
        try std.testing.expectEqual(@as(u64, 3), decoder.table.insert_count);
        try std.testing.expectEqual(@as(u64, 3), decoder.acknowledged_insert_count);
        try std.testing.expectEqual(3 - committed, try incrementTotal(&decoder));
        decoder.clearDecoderInstructions();
        try decoder.applyEncoderStreamFrame(&control, .{ .stream_id = 6, .data = bytes });
        try std.testing.expectEqual(@as(u64, 3), decoder.table.insert_count);
        try std.testing.expectEqual(@as(usize, 0), decoder.pendingDecoderInstructions().len);
        recovered = true;
        break;
    }
    try std.testing.expect(recovered);
}

test "HTTP/3 QPACK decoder preserves successful insert feedback before an invalid later instruction" {
    var decoder = Decoder.init(std.testing.allocator, 256, 4096);
    defer decoder.deinit();
    var control = http3.ControlState{};
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, std.testing.allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, std.testing.allocator, .{ .set_capacity = 256 });
    try http3.Qpack.writeEncoderInstruction(&bytes, std.testing.allocator, .{ .insert_literal = .{ .name = "x-progress", .value = "one" } });
    try http3.Qpack.writeEncoderInstruction(&bytes, std.testing.allocator, .{ .set_capacity = 512 });
    try std.testing.expectError(error.QpackEncoderStreamError, decoder.applyEncoderStreamFrame(&control, .{ .stream_id = 6, .data = bytes.items }));
    try std.testing.expectEqual(@as(u64, 1), decoder.table.insert_count);
    try std.testing.expectEqual(@as(u64, 1), try incrementTotal(&decoder));
}
