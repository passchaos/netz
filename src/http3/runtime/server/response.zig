const std = @import("std");
const http_date = @import("../../../internal/http_date.zig");
const http3 = @import("../../mod.zig");

pub const header_stack_capacity: usize = 16;
pub const date_value_len: usize = http_date.value_len;

pub const Prepared = struct {
    value: http3.Response,
    allocated_headers: ?[]http3.Qpack.HeaderField = null,

    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator) void {
        if (self.allocated_headers) |headers| allocator.free(headers);
        self.* = undefined;
    }
};

pub fn headerValue(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

/// Build the short-lived final-response view used by server runtimes. Common
/// header sets stay on the caller's stack; unusually large sets use an exact
/// fallback allocation. The Date bytes themselves borrow the shared
/// per-thread, per-second cache and are consumed synchronously by the codec.
pub fn prepare(
    allocator: std.mem.Allocator,
    response: http3.Response,
    automatic_date: ?*const [http_date.value_len]u8,
    stack: []http3.Qpack.HeaderField,
) std.mem.Allocator.Error!Prepared {
    const date = automatic_date orelse return .{ .value = response };
    if (headerValue(response.headers, "date") != null) {
        return .{ .value = response };
    }

    const count = std.math.add(usize, response.headers.len, 1) catch
        return error.OutOfMemory;
    const headers = if (count <= stack.len)
        stack[0..count]
    else
        try allocator.alloc(http3.Qpack.HeaderField, count);
    @memcpy(headers[0..response.headers.len], response.headers);
    headers[response.headers.len] = .{
        .name = "date",
        .value = date,
        // Date changes once per second. Keep the static-name reference but do
        // not churn the QPACK dynamic table with short-lived values.
        .never_indexed = true,
    };
    var value = response;
    value.headers = headers;
    return .{
        .value = value,
        .allocated_headers = if (headers.ptr == stack.ptr) null else headers,
    };
}

pub fn automaticDate(
    enabled: bool,
    io: std.Io,
    response: http3.Response,
) ?*const [http_date.value_len]u8 {
    if (!enabled or headerValue(response.headers, "date") != null) {
        return null;
    }
    return http_date.valueNow(io);
}

pub fn cachedDate(
    enabled: bool,
    io: std.Io,
) ?*const [http_date.value_len]u8 {
    if (!enabled) return null;
    return http_date.valueNow(io);
}

test "HTTP/3 automatic Date response view is stack-first and preserves explicit fields" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stack: [header_stack_capacity]http3.Qpack.HeaderField = undefined;
    var fail_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var generated = try prepare(
        fail_alloc.allocator(),
        .{ .status = 200, .headers = &.{.{
            .name = "content-type",
            .value = "text/plain",
        }} },
        automaticDate(true, io, .{ .status = 200 }),
        &stack,
    );
    defer generated.deinit(fail_alloc.allocator());
    try std.testing.expect(!fail_alloc.has_induced_failure);
    try std.testing.expect(generated.allocated_headers == null);
    const generated_date = headerValue(generated.value.headers, "date") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(date_value_len, generated_date.len);
    try std.testing.expectEqualStrings("GMT", generated_date[26..]);

    const explicit_value = "Sun, 06 Nov 1994 08:49:37 GMT";
    const explicit_response: http3.Response = .{
        .status = 200,
        .headers = &.{.{ .name = "DaTe", .value = explicit_value }},
    };
    var empty_stack: [0]http3.Qpack.HeaderField = .{};
    var explicit = try prepare(
        fail_alloc.allocator(),
        explicit_response,
        automaticDate(true, io, explicit_response),
        &empty_stack,
    );
    defer explicit.deinit(fail_alloc.allocator());
    try std.testing.expectEqualStrings(
        explicit_value,
        headerValue(explicit.value.headers, "date").?,
    );

    const disabled_response: http3.Response = .{ .status = 204 };
    var disabled = try prepare(
        fail_alloc.allocator(),
        disabled_response,
        automaticDate(false, io, disabled_response),
        &empty_stack,
    );
    defer disabled.deinit(fail_alloc.allocator());
    try std.testing.expect(headerValue(disabled.value.headers, "date") == null);
}

test "HTTP/3 automatic Date response view allocates only beyond stack capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();

    var headers: [header_stack_capacity]http3.Qpack.HeaderField = undefined;
    for (&headers, 0..) |*header, index| {
        header.* = .{
            .name = "x-test",
            .value = if (index == 0) "first" else "next",
        };
    }
    const response: http3.Response = .{ .status = 200, .headers = &headers };
    var stack: [header_stack_capacity]http3.Qpack.HeaderField = undefined;
    var prepared = try prepare(
        allocator,
        response,
        automaticDate(true, threaded.io(), response),
        &stack,
    );
    defer prepared.deinit(allocator);
    try std.testing.expect(prepared.allocated_headers != null);
    try std.testing.expectEqual(headers.len + 1, prepared.value.headers.len);
    try std.testing.expect(headerValue(prepared.value.headers, "date") != null);
}
