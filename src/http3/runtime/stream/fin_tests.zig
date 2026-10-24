const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const Reader = @import("reader.zig").Reader;

const Violation = enum { short_content, truncated_frame };

test "HTTP/3 reader known FIN preserves valid multi-frame DATA and trailers" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    inline for (.{ false, true }) |trailers| {
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(allocator);
        try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "3" },
        });
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = "ab", .consumed = 0 }).write(&bytes, allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = "c", .consumed = 0 }).write(&bytes, allocator);
        if (trailers) {
            block.clearRetainingCapacity();
            try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = "x-finished", .value = "yes" }});
            try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, allocator);
        }
        var reader = Reader.initResponse(allocator, 0, 256, .{});
        defer reader.deinit();
        try reader.insert(.{ .stream_id = 0, .data = bytes.items, .fin = true });
        var head = (try reader.next(table)) orelse return error.TestUnexpectedResult;
        defer head.deinit(allocator);
        try std.testing.expect(head == .head);
        try std.testing.expect((try reader.next(table)).? == .data_available);
        try std.testing.expectEqual(@as(usize, 2), try reader.availableDataBytes());
        var byte: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try reader.readData(&byte));
        try std.testing.expectEqualStrings("a", &byte);
        try std.testing.expectEqual(@as(usize, 1), try reader.skipData());
        try std.testing.expect((try reader.next(table)).? == .data_available);
        try std.testing.expectEqual(@as(usize, 1), try reader.readData(&byte));
        try std.testing.expectEqualStrings("c", &byte);
        if (trailers) {
            var event = (try reader.next(table)) orelse return error.TestUnexpectedResult;
            defer event.deinit(allocator);
            try std.testing.expect(event == .trailers);
            try std.testing.expectEqualStrings("yes", event.trailers.fields[0].value);
        }
        try std.testing.expect((try reader.next(table)).? == .finished);
        try std.testing.expectEqual(@as(usize, 3), reader.body_read);
    }
}

test "HTTP/3 reader rejects known final DATA violations before delivery" {
    inline for (.{ false, true }) |response| {
        inline for (.{ Violation.short_content, Violation.truncated_frame }) |violation| {
            try exercise(response, violation, false);
        }
    }
}

test "HTTP/3 reader rechecks final DATA after FIN arrives during partial delivery" {
    inline for (.{ false, true }) |response| {
        inline for (.{ Violation.short_content, Violation.truncated_frame }) |violation| {
            try exercise(response, violation, true);
        }
    }
}

fn exercise(comptime response: bool, violation: Violation, late_fin: bool) !void {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    if (response) {
        try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "3" },
        });
    } else {
        try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":method", .value = "POST" },     .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/final" },     .{ .name = ":authority", .value = "localhost" },
            .{ .name = "content-length", .value = "3" },
        });
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, allocator);
    try quic.varint.encode(&bytes, allocator, http3.FrameType.data);
    try quic.varint.encode(&bytes, allocator, if (violation == .short_content) 2 else 3);
    try bytes.appendSlice(allocator, "ab");
    var reader = if (response) Reader.initResponse(allocator, 0, 256, .{}) else Reader.initRequest(allocator, 0, 256, .{});
    defer reader.deinit();
    try reader.insert(.{ .stream_id = 0, .data = bytes.items[0 .. bytes.items.len - @as(usize, if (late_fin) 1 else 0)], .fin = !late_fin });
    var head = (try reader.next(table)) orelse return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    if (late_fin) {
        try std.testing.expect((try reader.next(table)).? == .data_available);
        var prefix: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try reader.readData(&prefix));
        try std.testing.expectEqualStrings("a", &prefix);
        try reader.insert(.{ .stream_id = 0, .offset = bytes.items.len - 1, .data = "b", .fin = true });
    }
    const expected = if (violation == .short_content) error.InvalidContentLength else error.BufferTooShort;
    const before = reader.readOffset();
    const body_before = reader.body_read;
    // Public data APIs must recheck the boundary even when DATA availability
    // was reported before the final size became known.
    if (late_fin) {
        try std.testing.expectError(expected, reader.availableDataBytes());
        var out = [_]u8{0xaa} ** 4;
        try std.testing.expectError(expected, reader.readData(&out));
        try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
        try std.testing.expectError(expected, reader.skipData());
        try std.testing.expectEqual(before, reader.readOffset());
    }
    try std.testing.expectError(expected, reader.next(table));
    try std.testing.expectEqual(body_before, reader.body_read);
}
