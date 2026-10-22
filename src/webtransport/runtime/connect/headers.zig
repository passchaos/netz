const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const Version = http3.WebTransportVersion;

pub fn protocol(version: Version) []const u8 {
    return version.protocol();
}

pub const stack_capacity: usize = 16;

pub const Context = enum { request, response };

/// Admission policy for the RFC 6454 Origin carried by WebTransport CONNECT.
///
/// Browser clients always send Origin. Non-browser clients are allowed to
/// omit it under the default policy, but any value they do send is checked.
pub const OriginPolicy = union(enum) {
    /// Accept an absent Origin or one matching `:scheme` and `:authority`.
    same_origin_or_absent,
    /// Require one valid Origin whose serialization exactly matches this
    /// borrowed allowlist. The entries must outlive the server using it.
    exact: []const []const u8,
    /// Explicitly accept an absent or any single syntactically valid Origin.
    allow_any,
};

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
    return prepareRequestForVersion(allocator, origin, additional, stack, .legacy);
}

pub fn prepareRequestForVersion(
    allocator: std.mem.Allocator,
    origin: []const u8,
    additional: []const http3.Qpack.HeaderField,
    stack: []http3.Qpack.HeaderField,
    version: Version,
) (error{ InvalidHeader, IntegerOverflow } || std.mem.Allocator.Error)!Prepared {
    try validate(additional, .request);
    const include_origin = origin.len != 0 and !std.mem.eql(u8, origin, "/");
    const prefix_count: usize = 2 +
        @as(usize, @intFromBool(include_origin));
    const count = std.math.add(usize, prefix_count, additional.len) catch
        return error.IntegerOverflow;
    const fields = try acquire(allocator, stack, count);
    var index: usize = 0;
    fields[index] = .{ .name = ":protocol", .value = protocol(version) };
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
    return validateRequestForVersion(request, .legacy);
}

pub fn validateRequestForVersion(request: anytype, version: Version) error{InvalidConnect}!void {
    if (!std.mem.eql(u8, request.method, "CONNECT") or
        !std.mem.eql(u8, request.scheme, "https") or
        request.authority == null or request.authority.?.len == 0 or
        request.path.len == 0 or
        !std.mem.eql(
            u8,
            find(request.headers, ":protocol") orelse "",
            protocol(version),
        ))
    {
        return error.InvalidConnect;
    }
    try validateOptionalCapsule(request.headers);
}

pub fn validateOrigin(
    request: anytype,
    policy: OriginPolicy,
) error{InvalidOrigin}!void {
    var origin: ?[]const u8 = null;
    for (request.headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "origin")) continue;
        if (origin != null or header.value.len == 0) {
            return error.InvalidOrigin;
        }
        origin = header.value;
    }

    const value = origin orelse return switch (policy) {
        .exact => error.InvalidOrigin,
        .same_origin_or_absent, .allow_any => {},
    };
    const supplied_origin: ?http3.Origin = if (std.mem.eql(u8, value, "null"))
        null
    else
        http3.originFromSerialized(value) catch return error.InvalidOrigin;
    switch (policy) {
        .allow_any => return,
        .exact => |allowed_origins| {
            for (allowed_origins) |allowed| {
                // RFC 6454 serializations are policy values. Keep this exact
                // so operators do not accidentally broaden an allowlist.
                if (std.mem.eql(u8, value, allowed)) return;
            }
            return error.InvalidOrigin;
        },
        .same_origin_or_absent => {
            const authority = request.authority orelse
                return error.InvalidOrigin;
            const request_origin = http3.requestOrigin(
                request.scheme,
                authority,
            ) catch return error.InvalidOrigin;
            if (!http3.sameOrigin(
                request_origin,
                supplied_origin orelse return error.InvalidOrigin,
            )) {
                return error.InvalidOrigin;
            }
        },
    }
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

test "WebTransport Origin policy defaults to same-origin or absent" {
    const Request = struct {
        scheme: []const u8 = "https",
        authority: ?[]const u8 = "Example.COM",
        headers: []const http3.Qpack.HeaderField,
    };
    try validateOrigin(Request{ .headers = &.{} }, .same_origin_or_absent);
    try validateOrigin(Request{ .headers = &.{.{
        .name = "origin",
        .value = "https://example.com:443",
    }} }, .same_origin_or_absent);
    try validateOrigin(.{
        .scheme = "https",
        .authority = @as(?[]const u8, "[2001:db8::1]:8443"),
        .headers = @as([]const http3.Qpack.HeaderField, &.{.{
            .name = "origin",
            .value = "https://[2001:db8::1]:8443",
        }}),
    }, .same_origin_or_absent);
    try std.testing.expectError(error.InvalidOrigin, validateOrigin(
        Request{ .headers = &.{.{
            .name = "origin",
            .value = "https://cross-origin.example",
        }} },
        .same_origin_or_absent,
    ));
    try std.testing.expectError(error.InvalidOrigin, validateOrigin(
        Request{ .headers = &.{.{ .name = "origin", .value = "null" }} },
        .same_origin_or_absent,
    ));
    try std.testing.expectError(error.InvalidOrigin, validateOrigin(
        Request{ .headers = &.{.{ .name = "origin", .value = "" }} },
        .same_origin_or_absent,
    ));
    try std.testing.expectError(error.InvalidOrigin, validateOrigin(
        Request{ .headers = &.{.{
            .name = "origin",
            .value = "https://example.com/path",
        }} },
        .same_origin_or_absent,
    ));
    try std.testing.expectError(error.InvalidOrigin, validateOrigin(
        Request{ .headers = &.{.{
            .name = "origin",
            .value = "https://example.com:8443",
        }} },
        .same_origin_or_absent,
    ));
}

test "WebTransport Origin policy handles exact allowlists and ambiguity" {
    const Request = struct {
        scheme: []const u8 = "https",
        authority: ?[]const u8 = "service.example",
        headers: []const http3.Qpack.HeaderField,
    };
    const allowed = [_][]const u8{ "https://app.example", "null" };
    try validateOrigin(Request{ .headers = &.{.{
        .name = "origin",
        .value = "https://app.example",
    }} }, .{ .exact = &allowed });
    try validateOrigin(Request{ .headers = &.{.{
        .name = "origin",
        .value = "null",
    }} }, .{ .exact = &allowed });
    try std.testing.expectError(
        error.InvalidOrigin,
        validateOrigin(Request{ .headers = &.{} }, .{ .exact = &allowed }),
    );
    try std.testing.expectError(error.InvalidOrigin, validateOrigin(
        Request{ .headers = &.{
            .{ .name = "origin", .value = "https://app.example" },
            .{ .name = "Origin", .value = "https://app.example" },
        } },
        .allow_any,
    ));
    try validateOrigin(Request{ .headers = &.{.{
        .name = "origin",
        .value = "https://untrusted.example",
    }} }, .allow_any);
    try std.testing.expectError(error.InvalidOrigin, validateOrigin(
        Request{ .headers = &.{.{
            .name = "origin",
            .value = "https://untrusted.example/path",
        }} },
        .allow_any,
    ));
}

test "WebTransport CONNECT token is bound to the negotiated wire family" {
    const allocator = std.testing.allocator;
    inline for (.{ Version.legacy, Version.draft16 }) |version| {
        var stack: [stack_capacity]http3.Qpack.HeaderField = undefined;
        var prepared = try prepareRequestForVersion(allocator, "https://example.test", &.{}, &stack, version);
        defer prepared.deinit(allocator);
        const request = struct {
            method: []const u8 = "CONNECT",
            scheme: []const u8 = "https",
            authority: ?[]const u8 = "example.test",
            path: []const u8 = "/wt",
            headers: []const http3.Qpack.HeaderField,
        }{ .headers = prepared.fields };
        try validateRequestForVersion(request, version);
        try std.testing.expectEqualStrings(protocol(version), find(prepared.fields, ":protocol").?);
        const other: Version = if (version == .legacy) .draft16 else .legacy;
        try std.testing.expectError(error.InvalidConnect, validateRequestForVersion(request, other));
    }
}
