//! Transactional HTTP/1 responses emitted before a WebSocket Upgrade exists.

const std = @import("std");
const http1 = @import("../../../http1/mod.zig");
const http1_write = @import("../../../http1/runtime/write.zig");
const headers = @import("headers.zig");
const storage = @import("storage.zig");

/// Prepare a final rejection while keeping the body borrowed. Negotiation and
/// HTTP framing remain owned by this adapter; no field descriptors or encoded
/// bytes are allocated until the exact response head fits the caller's limit.
pub fn prepare(
    allocator: std.mem.Allocator,
    request_method: http1.Method,
    status: u16,
    reason: []const u8,
    response_headers: []const http1.Header,
    body: []const u8,
    max_head_bytes: usize,
    scratch: *http1_write.Scratch,
) !http1_write.MessageParts {
    if (status < 300 or status > 599) return error.InvalidStatus;
    try headers.validateHttp1RejectionExtra(response_headers);
    try http1.validateReasonPhrase(reason);
    try http1.validateOutgoingResponseBodyForStatus(status, response_headers, body, &.{});
    // These rejections have fixed-length or status-suppressed bodies. The
    // adapter forbids caller framing fields, so only the runtime's default
    // Content-Length and our Connection: close need to be included here.
    var len: usize = "HTTP/1.1 ".len + 3 + 1 + 2 + "Connection: close\r\n".len + 2;
    len = std.math.add(usize, len, reason.len) catch return error.HeadersTooLarge;
    for (response_headers) |header| {
        len = std.math.add(usize, len, header.name.len) catch return error.HeadersTooLarge;
        len = std.math.add(usize, len, 2) catch return error.HeadersTooLarge;
        len = std.math.add(usize, len, header.value.len) catch return error.HeadersTooLarge;
        len = std.math.add(usize, len, 2) catch return error.HeadersTooLarge;
    }
    if (!http1.statusCodeForbidsBody(status)) {
        len = std.math.add(usize, len, std.fmt.count("Content-Length: {d}\r\n", .{body.len})) catch return error.HeadersTooLarge;
    }
    if (len > max_head_bytes) return error.HeadersTooLarge;
    const count = std.math.add(usize, response_headers.len, 1) catch return error.HeadersTooLarge;
    var stack: [storage.stack_capacity]http1.Header = undefined;
    const fields = try storage.acquire(http1.Header, allocator, &stack, count);
    defer storage.release(http1.Header, allocator, &stack, fields);
    @memcpy(fields[0..response_headers.len], response_headers);
    fields[response_headers.len] = .{ .name = "Connection", .value = "close" };
    try scratch.encoded.ensureTotalCapacityPrecise(allocator, len);
    const message = try http1_write.prepareResponse(allocator, .{
        .status = status,
        .reason = reason,
        .headers = fields,
        .body = body,
        .request_method = request_method,
    }, scratch);
    std.debug.assert(message.header.len == len);
    return message;
}

pub fn writeUnsupportedVersion(
    allocator: std.mem.Allocator,
    request_method: http1.Method,
    max_head_bytes: usize,
    context: anytype,
    comptime write: anytype,
) !void {
    const response_headers = [_]http1.Header{
        .{ .name = "Sec-WebSocket-Version", .value = "13" },
    };
    var scratch: http1_write.Scratch = .{};
    defer scratch.deinit(allocator);
    const message = try prepare(
        allocator,
        request_method,
        426,
        "Upgrade Required",
        &response_headers,
        &.{},
        max_head_bytes,
        &scratch,
    );
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

test "WebSocket unsupported version head limit precedes allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const Unreachable = struct {
        fn write(_: void, _: []const u8, _: []const u8) !void {
            return error.TestUnexpectedResult;
        }
    };
    try std.testing.expectError(error.HeadersTooLarge, writeUnsupportedVersion(failing.allocator(), .GET, 1, {}, Unreachable.write));
    try std.testing.expect(!failing.has_induced_failure);
}

test "WebSocket rejection exact head budget preserves status and body framing" {
    const field = [_]http1.Header{.{ .name = "X-Test", .value = "ok" }};
    const cases = .{
        .{ http1.Method.GET, @as(u16, 401), "Unauthorized", "denied", "HTTP/1.1 401 Unauthorized\r\nX-Test: ok\r\nConnection: close\r\nContent-Length: 6\r\n\r\n" },
        .{ http1.Method.GET, @as(u16, 503), "Service Unavailable", "please try later", "HTTP/1.1 503 Service Unavailable\r\nX-Test: ok\r\nConnection: close\r\nContent-Length: 16\r\n\r\n" },
        .{ http1.Method.HEAD, @as(u16, 401), "Unauthorized", "denied", "HTTP/1.1 401 Unauthorized\r\nX-Test: ok\r\nConnection: close\r\nContent-Length: 6\r\n\r\n" },
        .{ http1.Method.GET, @as(u16, 304), "Not Modified", "", "HTTP/1.1 304 Not Modified\r\nX-Test: ok\r\nConnection: close\r\n\r\n" },
        .{ http1.Method.GET, @as(u16, 599), "", "", "HTTP/1.1 599 \r\nX-Test: ok\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" },
    };
    inline for (cases) |case| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        var short: http1_write.Scratch = .{};
        try std.testing.expectError(error.HeadersTooLarge, prepare(failing.allocator(), case[0], case[1], case[2], &field, case[3], case[4].len - 1, &short));
        try std.testing.expect(!failing.has_induced_failure);
        // The exact head fits caller-owned storage even when every allocation
        // is denied. The body remains borrowed or is suppressed by HEAD/304.
        var bytes: [case[4].len]u8 = undefined;
        var exact: http1_write.Scratch = .{ .encoded = .initBuffer(&bytes) };
        const message = try prepare(failing.allocator(), case[0], case[1], case[2], &field, case[3], case[4].len, &exact);
        try std.testing.expectEqualStrings(case[4], message.header);
        try std.testing.expectEqualStrings(if (case[0] == .HEAD) "" else case[3], message.body);
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "WebSocket rejection validation precedes allocation under a short head budget" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var scratch: http1_write.Scratch = .{};
    try std.testing.expectError(error.InvalidStatus, prepare(failing.allocator(), .GET, 200, "OK", &.{}, "", 1, &scratch));
    try std.testing.expectError(error.MalformedStartLine, prepare(failing.allocator(), .GET, 401, "bad\r\nInjected", &.{}, "", 1, &scratch));
    try std.testing.expectError(error.InvalidHandshake, prepare(failing.allocator(), .GET, 401, "Unauthorized", &.{.{ .name = "Transfer-Encoding", .value = "chunked" }}, "", 1, &scratch));
    try std.testing.expectError(error.InvalidContentLength, prepare(failing.allocator(), .GET, 304, "Not Modified", &.{}, "invalid", 1, &scratch));
    try std.testing.expect(!failing.has_induced_failure);
}
