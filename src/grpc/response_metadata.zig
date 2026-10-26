//! Client response metadata policy, shared by every native gRPC RPC shape.
const std = @import("std");
const http2 = @import("../http2/mod.zig");
const wire = @import("wire.zig");
const details_mod = @import("status_details.zig");

pub const Error = wire.Error || details_mod.Error;

pub const Terminal = struct {
    status: wire.Status,
    status_message: []u8,
    status_details: ?details_mod.Owned,

    pub fn deinit(self: *Terminal, allocator: std.mem.Allocator) void {
        allocator.free(self.status_message);
        if (self.status_details) |*details| details.deinit();
        self.* = undefined;
    }
};

/// Intermediary error entities do not contain gRPC message envelopes. An
/// explicit terminal status still takes precedence over HTTP/media metadata.
pub fn parseBody(http_status: u16, headers: []const http2.Hpack.HeaderField, trailers: []const http2.Hpack.HeaderField) bool {
    const content_type = headerValue(headers, "content-type") orelse return false;
    return wire.isContentType(content_type) and
        (http_status == 200 or headerValue(headers, "grpc-status") != null or headerValue(trailers, "grpc-status") != null);
}

pub fn parseTerminal(
    allocator: std.mem.Allocator,
    http_status: u16,
    headers: []const http2.Hpack.HeaderField,
    trailers: []const http2.Hpack.HeaderField,
) Error!Terminal {
    const status_fields = if (headerValue(trailers, "grpc-status") != null) trailers else headers;
    const status_raw = headerValue(status_fields, "grpc-status");
    var status = statusFromHttp(http_status);
    var invalid_status = false;
    if (status_raw) |raw| {
        status = wire.Status.parse(raw) catch blk: {
            invalid_status = true;
            break :blk .unknown;
        };
        var count: usize = 0;
        for (status_fields) |field| if (std.mem.eql(u8, field.name, "grpc-status")) {
            count += 1;
        };
        if (count != 1) {
            status = .unknown;
            invalid_status = true;
        }
    }
    var status_details = try details_mod.fromMetadataAlloc(allocator, status, headers, trailers);
    errdefer if (status_details) |*details| details.deinit();
    const message_raw = headerValue(trailers, "grpc-message") orelse headerValue(headers, "grpc-message");
    const message = if (message_raw) |raw|
        try wire.decodeStatusMessageAlloc(allocator, raw)
    else if (status_raw == null)
        try std.fmt.allocPrint(allocator, "HTTP status {d} without grpc-status", .{http_status})
    else if (invalid_status)
        try allocator.dupe(u8, "Invalid grpc-status in response")
    else
        try allocator.alloc(u8, 0);
    return .{ .status = status, .status_message = message, .status_details = status_details };
}

pub fn statusFromHttp(status: u16) wire.Status {
    return switch (status) {
        400 => .internal,
        401 => .unauthenticated,
        403 => .permission_denied,
        404 => .unimplemented,
        429, 502, 503, 504 => .unavailable,
        else => .unknown,
    };
}

fn headerValue(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

test {
    _ = @import("response_metadata/tests.zig");
}
