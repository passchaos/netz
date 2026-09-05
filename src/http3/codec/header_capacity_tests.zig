const std = @import("std");
const http3 = @import("../mod.zig");

const large_header_count: usize = 80;

fn fillHeaders(headers: []http3.Qpack.HeaderField) void {
    for (headers, 0..) |*header, index| {
        header.* = .{
            .name = "x-many",
            .value = if ((index & 1) == 0) "even" else "odd",
        };
    }
}

test "HTTP/3 request and response writers exceed former 64 field limit" {
    const allocator = std.testing.allocator;
    var headers: [large_header_count]http3.Qpack.HeaderField = undefined;
    fillHeaders(&headers);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/many",
        .authority = "example.test",
        .headers = &headers,
        .body = "body",
    }).write(&encoded, allocator);
    var request = try http3.decodeRequest(allocator, encoded.items);
    defer request.deinit(allocator);
    try std.testing.expectEqual(headers.len + 5, request.headers.len);
    try std.testing.expectEqualStrings("body", request.body);

    encoded.clearRetainingCapacity();
    try (http3.Response{
        .status = 200,
        .headers = &headers,
        .body = "body",
    }).write(&encoded, allocator);
    var response = try http3.decodeResponse(allocator, encoded.items);
    defer response.deinit(allocator);
    try std.testing.expectEqual(headers.len + 2, response.headers.len);
    try std.testing.expectEqualStrings("body", response.body);
}

test "HTTP/3 dynamic and streaming writers exceed former 64 field limit" {
    const allocator = std.testing.allocator;
    var headers: [large_header_count]http3.Qpack.HeaderField = undefined;
    fillHeaders(&headers);

    const Encoder = struct {
        table: http3.Qpack.DynamicTable,

        fn init(a: std.mem.Allocator) @This() {
            return .{ .table = .init(a, 0) };
        }

        fn deinit(self: *@This()) void {
            self.table.deinit();
        }

        pub fn encodeFieldSection(
            self: *@This(),
            list: *std.ArrayList(u8),
            _: u64,
            fields: []const http3.Qpack.HeaderField,
        ) !void {
            try http3.Qpack.encodeDynamicBlock(
                list,
                self.table.allocator,
                fields,
                self.table,
            );
        }

        pub fn insertField(
            _: *@This(),
            _: []const u8,
            _: []const u8,
        ) !?u64 {
            return null;
        }
    };
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (http3.Request{
        .method = "POST",
        .path = "/dynamic-many",
        .authority = "example.test",
        .headers = &headers,
        .body = "x",
    }).writeDynamic(&encoded, allocator, .{}, 0, &encoder);
    var request = try http3.decodeRequest(allocator, encoded.items);
    defer request.deinit(allocator);
    try std.testing.expectEqual(headers.len + 5, request.headers.len);

    encoded.clearRetainingCapacity();
    const streaming = try (http3.Response{
        .status = 200,
        .headers = &headers,
    }).writeStreamingHeadDynamic(
        &encoded,
        allocator,
        .{},
        4,
        7,
        &encoder,
    );
    try std.testing.expectEqual(@as(?usize, 7), streaming.expected_length);
    const frame = try http3.Frame.parse(encoded.items);
    const fields = try http3.Qpack.decodeLiteralBlock(allocator, frame.payload);
    defer http3.Qpack.freeDecodedFields(allocator, fields);
    try std.testing.expectEqual(headers.len + 2, fields.len);
}

test "HTTP/3 large header assembly fails transactionally on allocation" {
    const allocator = std.testing.allocator;
    var headers: [large_header_count]http3.Qpack.HeaderField = undefined;
    fillHeaders(&headers);
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try std.testing.expectError(
        error.OutOfMemory,
        (http3.Response{ .status = 200, .headers = &headers }).write(
            &encoded,
            failing.allocator(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
}

test "HTTP/3 informational and Push Promise writers exceed former field limit" {
    const allocator = std.testing.allocator;
    var headers: [large_header_count]http3.Qpack.HeaderField = undefined;
    fillHeaders(&headers);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.InformationalResponse{
        .status = 103,
        .headers = &headers,
    }).write(&encoded, allocator);
    const info_frame = try http3.Frame.parse(encoded.items);
    const info_fields = try http3.Qpack.decodeLiteralBlock(
        allocator,
        info_frame.payload,
    );
    defer http3.Qpack.freeDecodedFields(allocator, info_fields);
    try std.testing.expectEqual(headers.len + 1, info_fields.len);

    const Encoder = struct {
        table: http3.Qpack.DynamicTable,

        fn init(a: std.mem.Allocator) @This() {
            return .{ .table = .init(a, 0) };
        }

        fn deinit(self: *@This()) void {
            self.table.deinit();
        }

        pub fn encodeFieldSection(
            self: *@This(),
            list: *std.ArrayList(u8),
            _: u64,
            fields: []const http3.Qpack.HeaderField,
        ) !void {
            try http3.Qpack.encodeDynamicBlock(
                list,
                self.table.allocator,
                fields,
                self.table,
            );
        }

        pub fn insertField(
            _: *@This(),
            _: []const u8,
            _: []const u8,
        ) !?u64 {
            return null;
        }
    };
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    encoded.clearRetainingCapacity();
    try http3.writePushPromiseDynamic(
        &encoded,
        allocator,
        0,
        .{
            .method = "GET",
            .path = "/many-push",
            .authority = "example.test",
            .headers = &headers,
        },
        .{},
        0,
        &encoder,
    );
    const promise_frame = try http3.Frame.parse(encoded.items);
    const promise = try http3.parsePushPromisePayload(promise_frame.payload);
    const promise_fields = try http3.Qpack.decodeLiteralBlock(
        allocator,
        promise.field_section,
    );
    defer http3.Qpack.freeDecodedFields(allocator, promise_fields);
    try std.testing.expectEqual(headers.len + 4, promise_fields.len);
}
