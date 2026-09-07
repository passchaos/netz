const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const Reader = @import("reader.zig").Reader;

test "HTTP/3 incremental reader streams DATA through bounded window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 100 * 1024;
    var table = http3.Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-stream", "owned");

    var fields: [6]http3.Qpack.HeaderField = .{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/large-stream" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "content-length", .value = undefined },
        .{ .name = "x-stream", .value = "owned" },
    };
    var content_length_buf: [32]u8 = undefined;
    fields[4].value = try std.fmt.bufPrint(
        &content_length_buf,
        "{}",
        .{body_len},
    );
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &fields, table);
    var message_prefix: std.ArrayList(u8) = .empty;
    defer message_prefix.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&message_prefix, allocator);
    try quic.varint.encode(&message_prefix, allocator, http3.FrameType.data);
    try quic.varint.encode(&message_prefix, allocator, body_len);

    var trailer_block: std.ArrayList(u8) = .empty;
    defer trailer_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &trailer_block,
        allocator,
        &.{.{ .name = "x-finished", .value = "yes" }},
        table,
    );
    var trailer_frame: std.ArrayList(u8) = .empty;
    defer trailer_frame.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = trailer_block.items,
        .consumed = 0,
    }).write(&trailer_frame, allocator);

    var reader = Reader.initRequest(allocator, 0, 512, .{});
    defer reader.deinit();
    var absolute_offset: u64 = 0;
    try reader.insert(.{
        .stream_id = 0,
        .offset = absolute_offset,
        .data = message_prefix.items,
    });
    absolute_offset += message_prefix.items.len;
    var head_event = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer head_event.deinit(allocator);
    try std.testing.expect(head_event == .head);
    try std.testing.expectEqualStrings(
        "/large-stream",
        head_event.head.request.path,
    );
    try std.testing.expectEqual(
        @as(?usize, body_len),
        head_event.head.request.content_length,
    );

    var body_checksum: u64 = 0;
    var body_read: usize = 0;
    var payload_chunk: [257]u8 = undefined;
    for (&payload_chunk, 0..) |*byte, index| byte.* = @truncate(index);
    var read_buf: [113]u8 = undefined;
    while (body_read < body_len) {
        const send_len = @min(payload_chunk.len, body_len - body_read);
        try reader.insert(.{
            .stream_id = 0,
            .offset = absolute_offset,
            .data = payload_chunk[0..send_len],
        });
        absolute_offset += send_len;
        while (true) {
            const event = (try reader.next(table)) orelse break;
            try std.testing.expect(event == .data_available);
            while (reader.hasPendingFrame()) {
                const available = try reader.availableDataBytes();
                const read = try reader.readData(&read_buf);
                try std.testing.expectEqual(
                    @min(available, read_buf.len),
                    read,
                );
                if (read == 0) break;
                for (read_buf[0..read]) |byte| body_checksum +%= byte;
                body_read += read;
            }
        }
        try std.testing.expect(reader.bufferedBytes() <= 512);
    }

    try reader.insert(.{
        .stream_id = 0,
        .offset = absolute_offset,
        .data = trailer_frame.items,
        .fin = true,
    });
    var trailers_event = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer trailers_event.deinit(allocator);
    try std.testing.expect(trailers_event == .trailers);
    try std.testing.expectEqualStrings(
        "yes",
        trailers_event.trailers.fields[0].value,
    );
    var finished = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
    try std.testing.expectEqual(body_len, body_read);

    var expected_checksum: u64 = 0;
    var remaining = body_len;
    while (remaining != 0) {
        const send_len = @min(payload_chunk.len, remaining);
        for (payload_chunk[0..send_len]) |byte| expected_checksum +%= byte;
        remaining -= send_len;
    }
    try std.testing.expectEqual(expected_checksum, body_checksum);
}

test "HTTP/3 incremental response reader emits informational and detects truncation" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);

    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "103" },
    }, table);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&bytes, allocator);
    block.clearRetainingCapacity();
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "4" },
    }, table);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&bytes, allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.data,
        .payload = "abc",
        .consumed = 0,
    }).write(&bytes, allocator);

    var reader = Reader.initResponse(allocator, 0, 128, .{});
    defer reader.deinit();
    try reader.insert(.{ .stream_id = 0, .data = bytes.items, .fin = true });
    var informational = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer informational.deinit(allocator);
    try std.testing.expect(informational == .head);
    try std.testing.expectEqual(
        @as(u16, 103),
        informational.head.response.status,
    );
    var final = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer final.deinit(allocator);
    try std.testing.expect(final == .head);
    try std.testing.expectEqual(@as(u16, 200), final.head.response.status);
    try std.testing.expect((try reader.next(table)).? == .data_available);
    var data: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try reader.readData(&data));
    try std.testing.expectError(error.InvalidContentLength, reader.next(table));
}

test "HTTP/3 incremental request reader distinguishes missing head and truncated frame" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();

    var missing_head = Reader.initRequest(allocator, 0, 32, .{});
    defer missing_head.deinit();
    try missing_head.insert(.{
        .stream_id = 0,
        .data = &.{},
        .fin = true,
    });
    try std.testing.expectError(
        error.RequestIncomplete,
        missing_head.next(table),
    );

    var truncated_frame = Reader.initRequest(allocator, 4, 32, .{});
    defer truncated_frame.deinit();
    try truncated_frame.insert(.{
        .stream_id = 4,
        // A two-byte HTTP/3 frame-type varint cut off by stream FIN.
        .data = &.{0x40},
        .fin = true,
    });
    try std.testing.expectError(
        error.BufferTooShort,
        truncated_frame.next(table),
    );

    var missing_response = Reader.initResponse(allocator, 0, 32, .{});
    defer missing_response.deinit();
    try missing_response.insert(.{
        .stream_id = 0,
        .data = &.{},
        .fin = true,
    });
    try std.testing.expectError(
        error.MissingStatus,
        missing_response.next(table),
    );
}

test "HTTP/3 incremental response reader owns dynamic PUSH_PROMISE before final head" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-promise-kind", "dynamic-asset");
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);

    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset.css" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-promise-kind", .value = "dynamic-asset" },
    }, table);
    try http3.writePushPromiseFrame(&bytes, allocator, 3, block.items);
    block.clearRetainingCapacity();
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "0" },
    }, table);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&bytes, allocator);

    var reader = Reader.initResponse(allocator, 0, 512, .{});
    var reader_owned = true;
    defer if (reader_owned) reader.deinit();
    try reader.insert(.{ .stream_id = 0, .data = bytes.items, .fin = true });
    var promise = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try std.testing.expectEqual(@as(u64, 3), promise.push_promise.push_id);
    try std.testing.expectEqualStrings(
        "/asset.css",
        promise.push_promise.request.path,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        promise.push_promise.request.qpack_section_acknowledgments,
    );
    try std.testing.expectEqualStrings(
        "dynamic-asset",
        promise.push_promise.request.headers[4].value,
    );
    var head = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    try std.testing.expectEqual(@as(u16, 200), head.head.response.status);
    reader.deinit();
    reader_owned = false;
    try std.testing.expectEqualStrings(
        "example.test",
        promise.push_promise.request.authority.?,
    );
}

test "HTTP/3 incremental response reader detects dynamic PUSH_PROMISE cancellation" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-promise-kind", "dynamic-asset");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset.css" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-promise-kind", .value = "dynamic-asset" },
    }, table);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writePushPromiseFrame(&bytes, allocator, 3, block.items);

    var reader = Reader.initResponse(allocator, 0, 512, .{});
    defer reader.deinit();
    try reader.insert(.{ .stream_id = 0, .data = bytes.items });
    try std.testing.expect(
        try reader.hasUnacknowledgedDynamicSection(table),
    );
}

test "HTTP/3 incremental reader retries blocked HEADERS transactionally" {
    const allocator = std.testing.allocator;
    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked-head", "ready-later");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "x-blocked-head", .value = "ready-later" },
    }, encoder_table);
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&frame, allocator);

    var decoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer decoder_table.deinit();
    try decoder_table.setCapacity(256);
    var reader = Reader.initResponse(allocator, 0, 512, .{});
    defer reader.deinit();
    try reader.insert(.{ .stream_id = 0, .data = frame.items, .fin = true });
    const read_offset = reader.readOffset();
    try std.testing.expectError(error.QpackBlocked, reader.next(decoder_table));
    try std.testing.expectEqual(read_offset, reader.readOffset());
    try std.testing.expect(reader.hasPendingFrame());

    _ = try decoder_table.insert("x-blocked-head", "ready-later");
    var head = (try reader.next(decoder_table)) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    try std.testing.expectEqual(@as(u16, 204), head.head.response.status);
}
