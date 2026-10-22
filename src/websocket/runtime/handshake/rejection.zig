//! Transactional HTTP/1 responses emitted before a WebSocket Upgrade exists.

const std = @import("std");
const http1 = @import("../../../http1/mod.zig");
const http1_write = @import("../../../http1/runtime/write.zig");

pub fn writeUnsupportedVersion(
    allocator: std.mem.Allocator,
    request_method: http1.Method,
    max_head_bytes: usize,
    context: anytype,
    comptime write: anytype,
) !void {
    const response_headers = [_]http1.Header{
        .{ .name = "Sec-WebSocket-Version", .value = "13" },
        .{ .name = "Connection", .value = "close" },
    };
    var scratch: http1_write.Scratch = .{};
    defer scratch.deinit(allocator);
    const message = try http1_write.prepareResponse(
        allocator,
        .{
            .status = 426,
            .reason = "Upgrade Required",
            .headers = &response_headers,
            .body = &.{},
            .request_method = request_method,
        },
        &scratch,
    );
    if (message.header.len > max_head_bytes) return error.HeadersTooLarge;
    try write(context, message.header, message.body);
}

test "WebSocket unsupported version response is bounded and canonical" {
    const allocator = std.testing.allocator;
    const Capture = struct {
        allocator: std.mem.Allocator,
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            self: *@This(),
            header: []const u8,
            body: []const u8,
        ) !void {
            try self.bytes.appendSlice(self.allocator, header);
            try self.bytes.appendSlice(self.allocator, body);
        }
    };
    var capture = Capture{ .allocator = allocator };
    defer capture.bytes.deinit(allocator);
    try writeUnsupportedVersion(
        allocator,
        .GET,
        4096,
        &capture,
        Capture.write,
    );
    var response = try http1.parseResponse(
        allocator,
        capture.bytes.items,
        .{},
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 426), response.status);
    try std.testing.expectEqualStrings(
        "13",
        response.header("sec-websocket-version").?,
    );
    try std.testing.expectEqualStrings(
        "close",
        response.header("connection").?,
    );
    try std.testing.expectEqual(@as(usize, 0), response.body.len);

    const previous_len = capture.bytes.items.len;
    try std.testing.expectError(
        error.HeadersTooLarge,
        writeUnsupportedVersion(
            allocator,
            .GET,
            1,
            &capture,
            Capture.write,
        ),
    );
    try std.testing.expectEqual(previous_len, capture.bytes.items.len);
}
