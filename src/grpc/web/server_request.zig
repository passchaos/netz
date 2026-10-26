//! Transport-independent gRPC-Web request classification and CORS decisions.
const http2 = @import("../../http2/mod.zig");
const cors = @import("cors/mod.zig");
const content_type = @import("content_type.zig");
const std = @import("std");

pub const Options = struct {
    max_message_size: usize = 16 * 1024 * 1024,
    cors_policy: ?cors.Policy = null,
};

pub const Classification = struct {
    status: ?u16 = null,
    cors_decision: ?cors.Decision = null,
    input_type: ?content_type.ContentType = null,
    output_type: ?content_type.ContentType = null,
};

pub fn classify(options: Options, method: []const u8, headers: []const http2.Hpack.HeaderField) cors.Error!Classification {
    var result: Classification = .{};
    if (options.cors_policy) |policy| {
        result.cors_decision = cors.evaluate(policy, method, headers) catch |err| switch (err) {
            error.InvalidCorsPolicy => return err,
            error.InvalidCorsRequest => return .{ .status = 400, .cors_decision = .{ .kind = .denied } },
        };
        result.status = switch (result.cors_decision.?.kind) {
            .denied => 403,
            .preflight => 204,
            else => null,
        };
        if (result.status != null) return result;
    }
    if (!std.mem.eql(u8, method, "POST")) {
        result.status = 405;
        return result;
    }
    for (headers) |field| {
        if (!std.ascii.eqlIgnoreCase(field.name, "content-type")) continue;
        if (result.input_type != null) {
            result.status = 400;
            return result;
        }
        result.input_type = content_type.parseContentType(field.value) catch {
            result.status = 415;
            return result;
        };
    }
    const input = result.input_type orelse {
        result.status = 415;
        return result;
    };
    result.output_type = content_type.negotiateResponseContentType(input, headers) catch |err| {
        result.status = if (err == error.InvalidWebAccept) 400 else 406;
        return result;
    };
    return result;
}

/// Browser permission fields are supplied by policy, preventing application
/// metadata from replacing or duplicating their values.
pub fn validateCorsMetadata(enabled: bool, fields: []const http2.Hpack.HeaderField) error{InvalidMetadata}!void {
    if (!enabled) return;
    for (fields) |field| if (std.ascii.startsWithIgnoreCase(field.name, "access-control-")) return error.InvalidMetadata;
}
