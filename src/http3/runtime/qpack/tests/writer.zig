const std = @import("std");
const http3 = @import("../../../mod.zig");
const QpackEncodeState = @import("../state.zig").QpackEncodeState;

test "HTTP/3 dynamic request writer inserts first and compresses after decoder feedback" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);

    const request = http3.Request{
        .method = "GET",
        .path = "/dynamic-writer",
        .authority = "example.com",
        .headers = &.{
            .{ .name = "x-service-release", .value = "2026.08.09" },
            .{ .name = "authorization", .value = "Bearer secret" },
            .{ .name = "cookie", .value = "session=secret" },
        },
    };
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try request.writeDynamic(&first, allocator, .{}, 0, &encoder);
    const first_headers = try http3.Frame.parse(first.items);
    var first_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        first_headers.payload,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &first_decoded);
    try std.testing.expectEqual(@as(u64, 0), first_decoded.required_insert_count);
    try std.testing.expect(encoder.table.findExact(
        "x-service-release",
        "2026.08.09",
    ) != null);
    try std.testing.expect(encoder.table.findName("authorization") == null);
    try std.testing.expect(encoder.table.findName("cookie") == null);
    try std.testing.expect(encoder.pendingEncoderInstructions().len != 0);

    encoder.known_received_count = encoder.table.insert_count;
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try request.writeDynamic(&second, allocator, .{}, 4, &encoder);
    const second_headers = try http3.Frame.parse(second.items);
    var second_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        second_headers.payload,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &second_decoded);
    try std.testing.expect(second_decoded.required_insert_count != 0);
    try std.testing.expect(second.items.len < first.items.len);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);
    try std.testing.expectEqual(
        @as(u64, 4),
        encoder.pending_sections.items[0].stream_id,
    );
}

test "HTTP/3 dynamic response writer tracks informational final and trailer sections" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-release", "netz-2026");
    encoder.known_received_count = encoder.table.insert_count;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http3.writeResponseSequenceDynamic(
        &encoded,
        allocator,
        &.{.{
            .status = 103,
            .headers = &.{.{ .name = "x-release", .value = "netz-2026" }},
        }},
        .{
            .status = 200,
            .headers = &.{.{ .name = "x-release", .value = "netz-2026" }},
            .body = "ok",
            .trailers = &.{.{ .name = "x-release", .value = "netz-2026" }},
        },
        .{},
        8,
        &encoder,
    );
    try std.testing.expectEqual(@as(usize, 3), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_section_index.count());
    try std.testing.expectEqual(
        @as(?usize, 0),
        encoder.pending_section_index.get(8),
    );
    for (encoder.pending_sections.items) |section| {
        try std.testing.expectEqual(@as(u64, 8), section.stream_id);
        try std.testing.expectEqual(@as(u64, 1), section.required_insert_count);
    }

    var cursor: usize = 0;
    var dynamic_sections: usize = 0;
    while (cursor < encoded.items.len) {
        const frame = try http3.Frame.parse(encoded.items[cursor..]);
        cursor += frame.consumed;
        if (frame.frame_type != http3.FrameType.headers) continue;
        var decoded = try http3.Qpack.decodeDynamicBlock(
            allocator,
            frame.payload,
            encoder.table,
        );
        defer http3.Qpack.freeDynamicBlock(allocator, &decoded);
        dynamic_sections += @intFromBool(decoded.required_insert_count != 0);
    }
    try std.testing.expectEqual(@as(usize, 3), dynamic_sections);
    encoder.abandonStream(8);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_section_index.count());
    try std.testing.expectEqual(@as(usize, 0), encoder.reference_counts.count());
}

test "HTTP/3 streaming request head adds and validates content length" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const streaming = try (http3.Request{
        .method = "POST",
        .path = "/streaming",
        .authority = "example.test",
    }).writeStreamingHeadDynamic(
        &encoded,
        allocator,
        .{},
        0,
        11,
        &encoder,
    );
    try std.testing.expectEqual(@as(?usize, 11), streaming.expected_length);
    try std.testing.expect(streaming.body_allowed);
    const frame = try http3.Frame.parse(encoded.items);
    try std.testing.expectEqual(http3.FrameType.headers, frame.frame_type);
    try std.testing.expectEqual(frame.consumed, encoded.items.len);
    var decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        frame.payload,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &decoded);
    var content_length_value: ?[]const u8 = null;
    for (decoded.fields) |field| {
        if (std.mem.eql(u8, field.name, "content-length")) {
            content_length_value = field.value;
        }
    }
    try std.testing.expectEqualStrings(
        "11",
        content_length_value orelse return error.TestUnexpectedResult,
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidContentLength,
        (http3.Request{
            .method = "POST",
            .path = "/streaming",
            .headers = &.{.{
                .name = "content-length",
                .value = "12",
            }},
        }).writeStreamingHeadDynamic(
            &encoded,
            allocator,
            .{},
            4,
            11,
            &encoder,
        ),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        (http3.Request{
            .method = "CONNECT",
            .path = "",
            .authority = "example.test:443",
        }).writeStreamingHeadDynamic(
            &encoded,
            allocator,
            .{},
            8,
            1,
            &encoder,
        ),
    );
}

test "HTTP/3 streaming response head enforces bodyless status" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    const streaming = try (http3.Response{
        .status = 200,
    }).writeStreamingHeadDynamic(
        &encoded,
        allocator,
        .{},
        0,
        null,
        &encoder,
    );
    try std.testing.expectEqual(@as(?usize, null), streaming.expected_length);
    try std.testing.expect(streaming.body_allowed);
    try std.testing.expectEqual(
        http3.FrameType.headers,
        (try http3.Frame.parse(encoded.items)).frame_type,
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidContentLength,
        (http3.Response{
            .status = 204,
        }).writeStreamingHeadDynamic(
            &encoded,
            allocator,
            .{},
            4,
            1,
            &encoder,
        ),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        (http3.Response{
            .status = 204,
            .headers = &.{.{
                .name = "content-length",
                .value = "0",
            }},
        }).writeStreamingHeadDynamic(
            &encoded,
            allocator,
            .{},
            8,
            null,
            &encoder,
        ),
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidContentLength,
        (http3.Response{
            .status = 205,
        }).writeStreamingHeadDynamic(
            &encoded,
            allocator,
            .{},
            12,
            1,
            &encoder,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    const reset = try (http3.Response{
        .status = 205,
        .headers = &.{.{
            .name = "content-length",
            .value = "0",
        }},
    }).writeStreamingHeadDynamic(
        &encoded,
        allocator,
        .{},
        16,
        null,
        &encoder,
    );
    try std.testing.expectEqual(@as(?usize, 0), reset.expected_length);
    try std.testing.expect(reset.body_allowed);
}

fn checkDynamicWriterAllocationFailure(allocator: std.mem.Allocator) !void {
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-existing", "existing-value");
    encoder.known_received_count = encoder.table.insert_count;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/transactional",
        .authority = "example.com",
        .headers = &.{
            .{ .name = "x-existing", .value = "existing-value" },
            .{ .name = "x-future", .value = "future-value" },
        },
        .body = "body",
        .trailers = &.{.{ .name = "x-trailer", .value = "trailer-value" }},
    }).writeDynamic(
        &encoded,
        allocator,
        .{},
        0,
        &encoder,
    );
}

test "HTTP/3 dynamic writer is leak-free under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicWriterAllocationFailure,
        .{},
    );
}

test "HTTP/3 dynamic HEADERS reuse one output allocation" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 0, 4096);
    defer encoder.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    const fields = [_]http3.Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/scratch" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
    };

    try encoder.encodeFieldSection(&output, 0, &fields);
    const required_capacity = output.items.len + 16;
    output.clearRetainingCapacity();
    try output.ensureTotalCapacity(allocator, required_capacity);
    const reusable_capacity = output.capacity;
    output.clearRetainingCapacity();

    var fail_after_output = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    encoder.allocator = fail_after_output.allocator();
    try (http3.Request{
        .method = "GET",
        .path = "/scratch",
        .authority = "example.test",
    }).writeDynamic(
        &output,
        fail_after_output.allocator(),
        .{},
        4,
        &encoder,
    );
    try std.testing.expect(!fail_after_output.has_induced_failure);
    try std.testing.expectEqual(reusable_capacity, output.capacity);
    const frame = try http3.Frame.parse(output.items);
    try std.testing.expectEqual(http3.FrameType.headers, frame.frame_type);
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    const decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        frame.payload,
        table,
    );
    defer http3.Qpack.freeDecodedFields(allocator, decoded.fields);
    try std.testing.expectEqual(@as(usize, 4), decoded.fields.len);
    try std.testing.expectEqualStrings("/scratch", decoded.fields[1].value);
}
