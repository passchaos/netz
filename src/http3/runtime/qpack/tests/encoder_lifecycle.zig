const std = @import("std");
const http3 = @import("../../../mod.zig");
const Encoder = @import("../encoder.zig").QpackEncodeState;

const Feedback = struct {
    control: http3.ControlState = .{},
    offset: u64 = 0,

    fn apply(self: *Feedback, encoder: *Encoder, instruction: http3.Qpack.DecoderInstruction) !void {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        if (self.offset == 0) try http3.writeQpackDecoderStreamPrefix(&bytes, std.testing.allocator);
        try http3.Qpack.writeDecoderInstruction(&bytes, std.testing.allocator, instruction);
        try encoder.applyDecoderStreamFrame(&self.control, .{ .stream_id = 10, .offset = self.offset, .data = bytes.items });
        self.offset += bytes.items.len;
    }
};

fn init(encoder: *Encoder, feedback: *Feedback, budget: usize) !void {
    encoder.* = .init(std.testing.allocator, 128, budget);
    errdefer encoder.deinit();
    try encoder.setCapacity(128);
    _ = try encoder.insertField("x-hold", "old");
    try feedback.apply(encoder, .{ .insert_count_increment = 1 });
}

const fields = [_]http3.Qpack.HeaderField{.{ .name = "x-hold", .value = "old" }};

test "HTTP/3 QPACK pending reference budget falls back to literals and recovers after feedback" {
    var encoder: Encoder = undefined;
    var feedback = Feedback{};
    try init(&encoder, &feedback, 96);
    defer encoder.deinit();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.testing.allocator);
    for ([_]u64{ 0, 4 }) |id| {
        block.clearRetainingCapacity();
        try encoder.encodeFieldSection(&block, id, &fields);
    }
    const retained = encoder.pending_section_bytes;
    try std.testing.expect(retained <= encoder.max_stream_buffer);
    try std.testing.expectEqual(@as(usize, 2), encoder.pending_sections.items.len);
    block.clearRetainingCapacity();
    try encoder.encodeFieldSection(&block, 8, &fields);
    var decoded = try http3.Qpack.decodeDynamicBlock(std.testing.allocator, block.items, encoder.table);
    defer http3.Qpack.freeDynamicBlock(std.testing.allocator, &decoded);
    try std.testing.expectEqual(@as(u64, 0), decoded.required_insert_count);
    try std.testing.expectEqualStrings("old", decoded.fields[0].value);
    try std.testing.expectEqual(retained, encoder.pending_section_bytes);
    try std.testing.expect(!encoder.hasPendingSections(8));
    try feedback.apply(&encoder, .{ .section_acknowledgment = 0 });
    block.clearRetainingCapacity();
    try encoder.encodeFieldSection(&block, 12, &fields);
    try std.testing.expectEqual(@as(u64, 1), (try http3.Qpack.decodeFieldSectionPrefix(block.items, encoder.table)).required_insert_count);
    try feedback.apply(&encoder, .{ .stream_cancellation = 4 });
    try feedback.apply(&encoder, .{ .stream_cancellation = 12 });
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_section_bytes);
    try std.testing.expectEqual(@as(usize, 0), encoder.reference_counts.count());
}

test "HTTP/3 QPACK rollback checkpoint survives acknowledgments that shift older sections" {
    var encoder: Encoder = undefined;
    var feedback = Feedback{};
    try init(&encoder, &feedback, 4096);
    defer encoder.deinit();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.testing.allocator);
    try encoder.encodeFieldSection(&block, 0, &fields);
    try encoder.encodeFieldSection(&block, 8, &fields);
    const checkpoint = encoder.checkpoint();
    try encoder.encodeFieldSection(&block, 4, &fields);
    try feedback.apply(&encoder, .{ .section_acknowledgment = 0 });
    encoder.rollbackAfter(checkpoint);
    try std.testing.expect(!encoder.hasPendingSections(4));
    try std.testing.expect(encoder.hasPendingSections(8));
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(0));
    try feedback.apply(&encoder, .{ .section_acknowledgment = 8 });
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_section_bytes);
}

test "HTTP/3 QPACK unsent later section rollback preserves an earlier section on the same stream" {
    var encoder: Encoder = undefined;
    var feedback = Feedback{};
    try init(&encoder, &feedback, 4096);
    defer encoder.deinit();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.testing.allocator);
    try encoder.encodeFieldSection(&block, 4, &fields);
    const checkpoint = encoder.checkpoint();
    try encoder.encodeFieldSection(&block, 4, &fields);
    encoder.rollbackAfter(checkpoint);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);
    try feedback.apply(&encoder, .{ .section_acknowledgment = 4 });
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);
}
