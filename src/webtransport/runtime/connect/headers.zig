const std = @import("std");
const http3 = @import("../../../http3/mod.zig");

pub const stack_capacity: usize = 16;

pub const Context = enum { request, response };

pub const Prepared = struct {
    fields: []const http3.Qpack.HeaderField,
    allocated: ?[]http3.Qpack.HeaderField = null,

    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator) void {
        if (self.allocated) |fields| allocator.free(fields);
        self.* = undefined;
    }
};

pub fn validate(
    headers: []const http3.Qpack.HeaderField,
    context: Context,
) error{InvalidHeader}!void {
    for (headers) |header| {
        try validateSyntax(header);
        // Pseudo-fields are constructed from typed options, and the adapter
        // owns Capsule-Protocol negotiation. Prevent generic metadata from
        // smuggling a duplicate or contradictory reserved field.
        if (std.mem.startsWith(u8, header.name, ":") or
            std.ascii.eqlIgnoreCase(
                header.name,
                http3.capsule.header_name,
            ) or
            std.ascii.eqlIgnoreCase(header.name, "content-length") or
            (context == .request and
                std.ascii.eqlIgnoreCase(header.name, "origin")))
        {
            return error.InvalidHeader;
        }
    }
}

pub fn prepareRequest(
    allocator: std.mem.Allocator,
    origin: []const u8,
    additional: []const http3.Qpack.HeaderField,
    stack: []http3.Qpack.HeaderField,
) (error{ InvalidHeader, IntegerOverflow } || std.mem.Allocator.Error)!Prepared {
    try validate(additional, .request);
    const include_origin = origin.len != 0 and !std.mem.eql(u8, origin, "/");
    const prefix_count: usize = 2 +
        @as(usize, @intFromBool(include_origin));
    const count = std.math.add(usize, prefix_count, additional.len) catch
        return error.IntegerOverflow;
    const fields = try acquire(allocator, stack, count);
    var index: usize = 0;
    fields[index] = .{ .name = ":protocol", .value = "webtransport" };
    index += 1;
    fields[index] = http3.capsule.protocol_header;
    index += 1;
    if (include_origin) {
        fields[index] = .{ .name = "origin", .value = origin };
        index += 1;
    }
    @memcpy(fields[index..], additional);
    return .{
        .fields = fields,
        .allocated = if (fields.ptr == stack.ptr) null else fields,
    };
}

pub fn prepareResponse(
    allocator: std.mem.Allocator,
    additional: []const http3.Qpack.HeaderField,
    stack: []http3.Qpack.HeaderField,
) (error{ InvalidHeader, IntegerOverflow } || std.mem.Allocator.Error)!Prepared {
    try validate(additional, .response);
    const count = std.math.add(usize, additional.len, 1) catch
        return error.IntegerOverflow;
    const fields = try acquire(allocator, stack, count);
    fields[0] = http3.capsule.protocol_header;
    @memcpy(fields[1..], additional);
    return .{
        .fields = fields,
        .allocated = if (fields.ptr == stack.ptr) null else fields,
    };
}

pub fn validateRequest(request: anytype) error{InvalidConnect}!void {
    if (!std.mem.eql(u8, request.method, "CONNECT") or
        !std.mem.eql(u8, request.scheme, "https") or
        request.authority == null or request.authority.?.len == 0 or
        request.path.len == 0 or
        !std.mem.eql(
            u8,
            find(request.headers, ":protocol") orelse "",
            "webtransport",
        ))
    {
        return error.InvalidConnect;
    }
    try validateOptionalCapsule(request.headers);
}

pub fn response(fields: []const http3.Qpack.HeaderField) http3.Response {
    return .{
        .status = 200,
        .headers = fields,
        .request_method = "CONNECT",
        .extended_connect = true,
    };
}

pub fn validateResponse(value: anytype) error{
    InvalidConnect,
    SessionRejected,
}!void {
    if (value.status < 200 or value.status >= 300) {
        return error.SessionRejected;
    }
    try validateOptionalCapsule(value.headers);
}

/// Modern WebTransport peers treat DATA capsules as intrinsic to Extended
/// CONNECT and may omit the older Capsule-Protocol field. Keep accepting that
/// shape, but reject any explicitly false or malformed structured-field item.
pub fn validateOptionalCapsule(
    fields: []const http3.Qpack.HeaderField,
) error{InvalidConnect}!void {
    if (find(fields, http3.capsule.header_name) == null) return;
    if (!(http3.capsule.protocolEnabled(fields) catch
        return error.InvalidConnect))
    {
        return error.InvalidConnect;
    }
}

fn find(
    fields: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}

fn acquire(
    allocator: std.mem.Allocator,
    stack: []http3.Qpack.HeaderField,
    count: usize,
) std.mem.Allocator.Error![]http3.Qpack.HeaderField {
    if (count <= stack.len) return stack[0..count];
    return allocator.alloc(http3.Qpack.HeaderField, count);
}

fn validateSyntax(header: http3.Qpack.HeaderField) error{InvalidHeader}!void {
    if (header.name.len == 0) return error.InvalidHeader;
    for (header.name) |byte| {
        if (!std.ascii.isLower(byte) and
            !std.ascii.isDigit(byte) and
            switch (byte) {
                '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => false,
                else => true,
            })
        {
            return error.InvalidHeader;
        }
    }
    for (header.value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) {
            return error.InvalidHeader;
        }
    }
}

test "WebTransport CONNECT headers are stack-first with exact fallback" {
    const allocator = std.testing.allocator;
    var stack: [stack_capacity]http3.Qpack.HeaderField = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var common = try prepareRequest(
        failing.allocator(),
        "https://example.test",
        &.{.{ .name = "x-extra", .value = "yes" }},
        &stack,
    );
    defer common.deinit(failing.allocator());
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expect(common.allocated == null);
    try std.testing.expectEqual(@as(usize, 4), common.fields.len);

    var many: [80]http3.Qpack.HeaderField = undefined;
    for (&many) |*header| {
        header.* = .{ .name = "x-many", .value = "value" };
    }
    var prepared = try prepareResponse(allocator, &many, &stack);
    defer prepared.deinit(allocator);
    try std.testing.expect(prepared.allocated != null);
    try std.testing.expectEqual(many.len + 1, prepared.fields.len);
}

test "WebTransport CONNECT header fallback is transactional on OOM" {
    const allocator = std.testing.allocator;
    var many: [80]http3.Qpack.HeaderField = undefined;
    for (&many) |*header| {
        header.* = .{ .name = "x-many", .value = "value" };
    }
    var stack: [stack_capacity]http3.Qpack.HeaderField = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        prepareRequest(
            failing.allocator(),
            "https://example.test",
            &many,
            &stack,
        ),
    );
}

test "WebTransport CONNECT protocol fields and responses are validated" {
    const allocator = std.testing.allocator;
    var stack: [stack_capacity]http3.Qpack.HeaderField = undefined;
    var prepared = try prepareRequest(
        allocator,
        "https://example.com",
        &.{},
        &stack,
    );
    defer prepared.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), prepared.fields.len);
    try std.testing.expectEqualStrings(
        "https://example.com",
        find(prepared.fields, "origin").?,
    );
    try validateRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .path = "/",
        .authority = @as(?[]const u8, "example.com"),
        .headers = prepared.fields,
    });

    const without_capsule = [_]http3.Qpack.HeaderField{.{
        .name = ":protocol",
        .value = "webtransport",
    }};
    try validateRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .path = "/",
        .authority = @as(?[]const u8, "example.com"),
        .headers = &without_capsule,
    });
    const false_capsule = [_]http3.Qpack.HeaderField{
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = "capsule-protocol", .value = "?0" },
    };
    try std.testing.expectError(error.InvalidConnect, validateRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .path = "/",
        .authority = @as(?[]const u8, "example.com"),
        .headers = &false_capsule,
    }));
    try std.testing.expectError(error.InvalidConnect, validateRequest(.{
        .method = "CONNECT",
        .scheme = "http",
        .path = "/",
        .authority = @as(?[]const u8, "example.com"),
        .headers = prepared.fields,
    }));

    try validateResponse(response(&.{http3.capsule.protocol_header}));
    try validateResponse(.{
        .status = 200,
        .headers = @as([]const http3.Qpack.HeaderField, &.{}),
    });
    try std.testing.expectError(error.SessionRejected, validateResponse(.{
        .status = 403,
        .headers = @as([]const http3.Qpack.HeaderField, &.{}),
    }));
}

test "WebTransport additional CONNECT fields reject reserved overrides" {
    try std.testing.expectError(error.InvalidHeader, validate(&.{.{
        .name = ":path",
        .value = "/override",
    }}, .request));
    try std.testing.expectError(error.InvalidHeader, validate(&.{.{
        .name = "Capsule-Protocol",
        .value = "?0",
    }}, .response));
    try std.testing.expectError(error.InvalidHeader, validate(&.{.{
        .name = "content-length",
        .value = "0",
    }}, .response));
    const many = [_]http3.Qpack.HeaderField{.{
        .name = "x-extra",
        .value = "value",
    }} ** 80;
    try validate(&many, .request);
}
