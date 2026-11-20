//! Short-lived response preparation shared by concurrent buffered send paths.
const std = @import("std");
const http3 = @import("../../mod.zig");
const server_response = @import("../server/response.zig");

pub fn prepare(
    allocator: std.mem.Allocator,
    response: http3.Response,
    body_length: ?usize,
    data: []const u8,
    request_method: ?[]const u8,
    stack: []http3.Qpack.HeaderField,
    length_buffer: *[20]u8,
) http3.Error!server_response.Prepared {
    var value = response;
    value.body = data;
    value.request_method = request_method;
    const length = body_length orelse return .{ .value = value };
    if (try http3.contentLength(value.headers)) |declared| {
        if (declared != length) return error.InvalidContentLength;
        return .{ .value = value };
    }
    // 204 and successful traditional CONNECT cannot carry Content-Length.
    if (value.status == 204 or (value.request_method != null and
        std.mem.eql(u8, value.request_method.?, "CONNECT") and
        !value.extended_connect and value.successful())) return .{ .value = value };
    const count = std.math.add(usize, value.headers.len, 1) catch return error.OutOfMemory;
    const headers = if (count <= stack.len) stack[0..count] else try allocator.alloc(http3.Qpack.HeaderField, count);
    @memcpy(headers[0..value.headers.len], value.headers);
    headers[value.headers.len] = .{
        .name = "content-length",
        .value = std.fmt.bufPrint(length_buffer, "{d}", .{length}) catch unreachable,
    };
    value.headers = headers;
    return .{ .value = value, .allocated_headers = if (headers.ptr == stack.ptr) null else headers };
}
