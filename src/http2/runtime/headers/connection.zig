const std = @import("std");
const http2 = @import("../../mod.zig");
const early_data = @import("../../../http/early_data.zig");

pub const BlockKind = enum {
    request,
    response,
    request_trailers,
    response_trailers,
};

const connection_value_stack_capacity: usize = 8;

/// Strip HTTP/1 connection-specific metadata before an outbound HTTP/2 field
/// block is validated or encoded. All Connection values are collected before
/// compaction so a late field can nominate an earlier or later header.
pub fn stripConnectionHeaders(
    allocator: std.mem.Allocator,
    headers: *std.ArrayList(http2.Hpack.HeaderField),
    kind: BlockKind,
) (std.mem.Allocator.Error || early_data.Error)!void {
    switch (kind) {
        .request => try early_data.validateOutboundRequestHeaders(
            headers.items,
        ),
        .response, .request_trailers, .response_trailers => try early_data.validateForbiddenFields(headers.items),
    }
    var connection_count: usize = 0;
    for (headers.items) |header| {
        connection_count += @intFromBool(
            std.ascii.eqlIgnoreCase(header.name, "connection"),
        );
    }

    var stack: [connection_value_stack_capacity][]const u8 = undefined;
    const values = if (connection_count <= stack.len)
        stack[0..connection_count]
    else
        try allocator.alloc([]const u8, connection_count);
    defer if (values.ptr != stack[0..].ptr) allocator.free(values);

    var connection_index: usize = 0;
    for (headers.items) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        values[connection_index] = header.value;
        connection_index += 1;
    }

    var write_index: usize = 0;
    for (headers.items) |header| {
        if (stripHeader(header, kind, values)) continue;
        headers.items[write_index] = header;
        write_index += 1;
    }
    headers.shrinkRetainingCapacity(write_index);
}

fn stripHeader(
    header: http2.Hpack.HeaderField,
    kind: BlockKind,
    connection_values: []const []const u8,
) bool {
    if (std.ascii.eqlIgnoreCase(header.name, "connection")) return true;
    if (connectionSpecificHeaderName(header.name)) return true;
    // RFC 8470 makes this replay-risk signal end-to-end across gateways.
    // Never let an HTTP/1 Connection token silently erase it during H2
    // conversion; response/trailer placement is rejected after compaction.
    if (early_data.isHeaderName(header.name)) return false;
    if (std.ascii.eqlIgnoreCase(header.name, "te") and
        (kind != .request or
            !std.ascii.eqlIgnoreCase(
                std.mem.trim(u8, header.value, " \t"),
                "trailers",
            )))
    {
        return true;
    }

    for (connection_values) |value| {
        var tokens = std.mem.splitScalar(u8, value, ',');
        while (tokens.next()) |raw_token| {
            const token = std.mem.trim(u8, raw_token, " \t");
            if (token.len != 0 and
                std.ascii.eqlIgnoreCase(header.name, token)) return true;
        }
    }
    return false;
}

pub fn connectionSpecificHeaderName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade");
}

test "HTTP/2 connection nominations beyond 256 are all stripped" {
    const allocator = std.testing.allocator;
    var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer fields.deinit(allocator);
    for (0..256) |_| {
        try fields.append(allocator, .{
            .name = "connection",
            .value = "x-decoy",
        });
    }
    try fields.appendSlice(allocator, &.{
        .{ .name = "connection", .value = "x-late-hop" },
        .{ .name = "x-decoy", .value = "secret-a" },
        .{ .name = "x-late-hop", .value = "secret-b" },
        .{ .name = "te", .value = "trailers" },
        .{ .name = "x-end-to-end", .value = "kept" },
    });

    try stripConnectionHeaders(allocator, &fields, .request);
    try std.testing.expectEqual(@as(usize, 2), fields.items.len);
    try std.testing.expectEqualStrings("te", fields.items[0].name);
    try std.testing.expectEqualStrings("x-end-to-end", fields.items[1].name);
}

test "HTTP/2 connection stripping is stack-first and transactional on OOM" {
    const allocator = std.testing.allocator;
    var common: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer common.deinit(allocator);
    try common.appendSlice(allocator, &.{
        .{ .name = "connection", .value = "x-hop" },
        .{ .name = "x-hop", .value = "secret" },
        .{ .name = "x-keep", .value = "yes" },
    });
    var fail_common = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try stripConnectionHeaders(fail_common.allocator(), &common, .request);
    try std.testing.expect(!fail_common.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), common.items.len);

    var overflow: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer overflow.deinit(allocator);
    for (0..connection_value_stack_capacity + 1) |_| {
        try overflow.append(allocator, .{
            .name = "connection",
            .value = "x-hop",
        });
    }
    try overflow.append(allocator, .{ .name = "x-hop", .value = "secret" });
    const original_len = overflow.items.len;
    var fail_overflow = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        stripConnectionHeaders(fail_overflow.allocator(), &overflow, .request),
    );
    try std.testing.expectEqual(original_len, overflow.items.len);
    try std.testing.expectEqualStrings("connection", overflow.items[0].name);
}

test "HTTP/2 TE trailers is retained only for requests" {
    const allocator = std.testing.allocator;
    var request: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer request.deinit(allocator);
    try request.append(allocator, .{ .name = "te", .value = " trailers \t" });
    try stripConnectionHeaders(allocator, &request, .request);
    try std.testing.expectEqual(@as(usize, 1), request.items.len);

    var response: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer response.deinit(allocator);
    try response.append(allocator, .{ .name = "te", .value = "trailers" });
    try stripConnectionHeaders(allocator, &response, .response);
    try std.testing.expectEqual(@as(usize, 0), response.items.len);
}

test "HTTP/2 outbound conversion preserves canonical Early-Data" {
    const allocator = std.testing.allocator;
    var request: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer request.deinit(allocator);
    try request.appendSlice(allocator, &.{
        .{ .name = "connection", .value = "early-data, x-hop" },
        .{ .name = "early-data", .value = "1" },
        .{ .name = "x-hop", .value = "remove" },
    });
    try stripConnectionHeaders(allocator, &request, .request);
    try std.testing.expectEqual(@as(usize, 1), request.items.len);
    try std.testing.expectEqualStrings("early-data", request.items[0].name);

    request.clearRetainingCapacity();
    try request.append(allocator, .{
        .name = "early-data",
        .value = "invalid",
    });
    try std.testing.expectError(
        error.InvalidHeader,
        stripConnectionHeaders(allocator, &request, .request),
    );
    try std.testing.expectEqual(@as(usize, 1), request.items.len);
    try std.testing.expectEqualStrings("invalid", request.items[0].value);
    try std.testing.expectError(
        error.InvalidHeader,
        stripConnectionHeaders(allocator, &request, .response),
    );
}
