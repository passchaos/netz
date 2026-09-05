const std = @import("std");
const http3 = @import("../../../../mod.zig");
const aggregate = @import("../aggregate.zig");

test "HTTP/3 push aggregate transfers owned response without copying" {
    const allocator = std.testing.allocator;
    const headers = try allocator.alloc(http3.Qpack.HeaderField, 1);
    headers[0] = .{ .name = "x-head", .value = "one" };
    const trailers = try allocator.alloc(http3.Qpack.HeaderField, 1);
    trailers[0] = .{ .name = "x-trailer", .value = "two" };
    const body = try allocator.dupe(u8, "payload");
    const body_ptr = body.ptr;

    var state: aggregate.State = .{
        .head = .{
            .status = 200,
            .headers = headers,
            .content_length = body.len,
            .body_allowed = true,
            .consumed = 0,
            .qpack_section_acknowledgments = 1,
        },
        .trailers = .{
            .fields = trailers,
            .qpack_section_acknowledgments = 2,
        },
        .body = .fromOwnedSlice(body),
        .push_id = 7,
        .request_stream_id = 4,
        .stream_id = 15,
        .finished = true,
    };
    defer state.deinit(allocator);

    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var response = try state.takeResponse(fail_first.allocator());
    defer response.deinit(fail_first.allocator());

    try std.testing.expect(!fail_first.has_induced_failure);
    try std.testing.expectEqual(body_ptr, response.response.body.ptr);
    try std.testing.expectEqualStrings("payload", response.response.body);
    try std.testing.expectEqual(@as(u64, 7), response.push_id);
    try std.testing.expectEqual(@as(u62, 4), response.request_stream_id);
    try std.testing.expectEqual(@as(u62, 15), response.stream_id);
    try std.testing.expectEqual(
        @as(usize, 3),
        response.response.qpack_section_acknowledgments,
    );
    try std.testing.expect(!state.active());
    try std.testing.expectEqual(@as(usize, 0), state.body.items.len);
}

test "HTTP/3 push aggregate rejects unfinished state" {
    var state: aggregate.State = .{};
    try std.testing.expectError(
        error.UnexpectedStream,
        state.takeResponse(std.testing.allocator),
    );
}

test "HTTP/3 push aggregate transfers response ownership without allocation" {
    const allocator = std.testing.allocator;
    const headers = try allocator.alloc(http3.Qpack.HeaderField, 1);
    headers[0] = .{ .name = "x-head", .value = "one" };
    const trailers = try allocator.alloc(http3.Qpack.HeaderField, 1);
    trailers[0] = .{ .name = "x-trailer", .value = "two" };
    const body = try allocator.dupe(u8, "payload");
    const body_ptr = body.ptr;

    var state: aggregate.State = .{
        .head = .{
            .status = 200,
            .headers = headers,
            .content_length = body.len,
            .body_allowed = true,
            .consumed = 0,
            .qpack_section_acknowledgments = 1,
        },
        .trailers = .{
            .fields = trailers,
            .qpack_section_acknowledgments = 2,
        },
        .body = .fromOwnedSlice(body),
        .push_id = 7,
        .request_stream_id = 4,
        .stream_id = 15,
        .finished = true,
    };
    defer state.deinit(allocator);

    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var response = try state.takeResponse(fail_first.allocator());
    defer response.deinit(fail_first.allocator());

    try std.testing.expect(!fail_first.has_induced_failure);
    try std.testing.expectEqual(body_ptr, response.response.body.ptr);
    try std.testing.expectEqualStrings("payload", response.response.body);
    try std.testing.expectEqual(@as(u64, 7), response.push_id);
    try std.testing.expectEqual(@as(u62, 4), response.request_stream_id);
    try std.testing.expectEqual(@as(u62, 15), response.stream_id);
    try std.testing.expectEqual(
        @as(usize, 3),
        response.response.qpack_section_acknowledgments,
    );
    try std.testing.expect(!state.active());
    try std.testing.expectEqual(@as(usize, 0), state.body.items.len);
}


test "HTTP/3 push aggregate preserves state when body transfer is OOM" {
    const allocator = std.testing.allocator;
    var body = try std.ArrayList(u8).initCapacity(allocator, 32);
    try body.appendSlice(allocator, "partial");
    const body_ptr = body.allocatedSlice().ptr;
    const headers = try allocator.alloc(http3.Qpack.HeaderField, 0);
    var state: aggregate.State = .{
        .head = .{
            .status = 200,
            .headers = headers,
            .content_length = 7,
            .body_allowed = true,
            .consumed = 0,
            .qpack_section_acknowledgments = 0,
        },
        .body = body,
        .push_id = 9,
        .request_stream_id = 8,
        .stream_id = 19,
        .finished = true,
    };
    defer state.deinit(allocator);

    var fail_transfer = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        state.takeResponse(fail_transfer.allocator()),
    );
    try std.testing.expect(fail_transfer.has_induced_failure);
    try std.testing.expect(state.active());
    try std.testing.expect(state.finished);
    try std.testing.expect(state.head != null);
    try std.testing.expectEqual(body_ptr, state.body.allocatedSlice().ptr);
    try std.testing.expectEqualStrings("partial", state.body.items);

    var response = try state.takeResponse(allocator);
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("partial", response.response.body);
    try std.testing.expect(!state.active());
}
