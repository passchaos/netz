const std = @import("std");
const http3 = @import("mod.zig");

const Observation = struct {
    statuses: [2]u16 = undefined,
    headers_valid: bool = true,
    count: usize = 0,

    fn observe(
        context_ptr: *anyopaque,
        response: http3.InformationalResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context_ptr));
        if (self.count >= self.statuses.len) {
            self.headers_valid = false;
            return;
        }
        const expected_name = if (response.status == 103)
            "link"
        else
            "x-progress";
        const expected_value = if (response.status == 103)
            "</style.css>"
        else
            "half";
        self.headers_valid = self.headers_valid and std.mem.eql(
            u8,
            findHeader(response.headers, expected_name) orelse "",
            expected_value,
        );
        self.statuses[self.count] = response.status;
        self.count += 1;
    }
};

fn findHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn writeInformationalSequence(
    allocator: std.mem.Allocator,
    count: usize,
) ![]u8 {
    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);
    for (0..count) |index| {
        try (http3.InformationalResponse{
            .status = if ((index & 1) == 0) 103 else 102,
            .headers = if ((index & 1) == 0)
                &.{.{ .name = "link", .value = "</style.css>" }}
            else
                &.{.{ .name = "x-progress", .value = "half" }},
        }).write(&encoded, allocator);
    }
    try (http3.Response{
        .status = 200,
        .headers = &.{.{ .name = "x-final", .value = "yes" }},
        .body = "final",
    }).write(&encoded, allocator);
    return encoded.toOwnedSlice(allocator);
}

test "HTTP/3 aggregate decoder observes bounded informational responses" {
    const allocator = std.testing.allocator;
    const encoded = try writeInformationalSequence(allocator, 2);
    defer allocator.free(encoded);

    var observation: Observation = .{};
    var response = try http3.decodeResponseWithOptions(allocator, encoded, .{
        .max_informational_responses = 2,
        .informational = .{
            .context = &observation,
            .on_response = Observation.observe,
        },
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        observation.statuses[0..observation.count],
    );
    try std.testing.expect(observation.headers_valid);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("yes", findHeader(
        response.headers,
        "x-final",
    ).?);
    try std.testing.expectEqualStrings("final", response.body);

    const excessive = try writeInformationalSequence(allocator, 3);
    defer allocator.free(excessive);
    try std.testing.expectError(
        error.TooManyInformationalResponses,
        http3.decodeResponseWithOptions(allocator, excessive, .{
            .max_informational_responses = 2,
        }),
    );

    const default_excessive = try writeInformationalSequence(
        allocator,
        http3.default_max_informational_responses + 1,
    );
    defer allocator.free(default_excessive);
    try std.testing.expectError(
        error.TooManyInformationalResponses,
        http3.decodeResponse(allocator, default_excessive),
    );
}

test "HTTP/3 response-head decoder observes and bounds informational heads" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    const encoded = try writeInformationalSequence(allocator, 2);
    defer allocator.free(encoded);

    var observation: Observation = .{};
    var head = try http3.decodeResponseHeadWithDynamicTableAndOptions(
        allocator,
        encoded,
        .{},
        table,
        .{
            .max_informational_responses = 2,
            .informational = .{
                .context = &observation,
                .on_response = Observation.observe,
            },
        },
    );
    defer head.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        observation.statuses[0..observation.count],
    );
    try std.testing.expect(observation.headers_valid);
    try std.testing.expectEqual(@as(u16, 200), head.status);

    const excessive = try writeInformationalSequence(allocator, 3);
    defer allocator.free(excessive);
    try std.testing.expectError(
        error.TooManyInformationalResponses,
        http3.decodeResponseHeadWithDynamicTableAndOptions(
            allocator,
            excessive,
            .{},
            table,
            .{ .max_informational_responses = 2 },
        ),
    );
}

test "HTTP/3 aggregate decoder rejects informational content length" {
    const allocator = std.testing.allocator;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "103" },
        .{ .name = "content-length", .value = "0" },
    });
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (http3.Response{ .status = 204 }).write(&encoded, allocator);
    try std.testing.expectError(
        error.InvalidContentLength,
        http3.decodeResponse(allocator, encoded.items),
    );
}
