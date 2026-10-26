const std = @import("std");
const cors = @import("mod.zig");
const http2 = @import("../../../http2/mod.zig");

const policy: cors.Policy = .{ .allowed_origins = &.{"https://app.example"}, .allow_credentials = true };

test "gRPC-Web CORS validates origins methods and repeated requested header lists" {
    const accepted = try cors.evaluate(policy, "OPTIONS", &.{
        .{ .name = "Origin", .value = "HTTPS://APP.EXAMPLE:443" },
        .{ .name = "Access-Control-Request-Method", .value = "POST" },
        .{ .name = "Access-Control-Request-Headers", .value = "Content-Type, X-Grpc-Web" },
        .{ .name = "Access-Control-Request-Headers", .value = "Authorization" },
    });
    try std.testing.expectEqual(.preflight, accepted.kind);
    try std.testing.expectEqualStrings("HTTPS://APP.EXAMPLE:443", accepted.origin.?);
    for ([_][]const u8{ "https://evil.example", "https://app.example:444", "http://app.example", "null" }) |origin| {
        try std.testing.expectEqual(.denied, (try cors.evaluate(policy, "POST", &.{.{ .name = "origin", .value = origin }})).kind);
    }
    try std.testing.expectEqual(.denied, (try cors.evaluate(policy, "OPTIONS", &.{
        .{ .name = "origin", .value = "https://app.example" },
        .{ .name = "access-control-request-method", .value = "DELETE" },
    })).kind);
    try std.testing.expectEqual(.denied, (try cors.evaluate(policy, "OPTIONS", &.{
        .{ .name = "origin", .value = "https://app.example" },
        .{ .name = "access-control-request-method", .value = "POST" },
        .{ .name = "access-control-request-headers", .value = "x-unlisted" },
    })).kind);
    try std.testing.expectEqual(.none, (try cors.evaluate(policy, "POST", &.{})).kind);
}

test "gRPC-Web CORS rejects ambiguous fields and invalid credentials policy" {
    try std.testing.expectError(error.InvalidCorsPolicy, (cors.Policy{ .allow_any_origin = true, .allow_credentials = true }).validate());
    for ([_][]const u8{ "https://app.example/", "https://user@app.example", "https://app.example?x", "https://app.example#x", "https://app.example\r\nfoo", "https://%61pp.example" }) |origin| {
        try std.testing.expectError(error.InvalidCorsRequest, cors.evaluate(policy, "POST", &.{.{ .name = "origin", .value = origin }}));
    }
    try std.testing.expectError(error.InvalidCorsRequest, cors.evaluate(policy, "POST", &.{
        .{ .name = "origin", .value = "https://app.example" },
        .{ .name = "Origin", .value = "https://app.example" },
    }));
    try std.testing.expectError(error.InvalidCorsRequest, cors.evaluate(policy, "OPTIONS", &.{
        .{ .name = "origin", .value = "https://app.example" },
        .{ .name = "access-control-request-method", .value = "POST" },
        .{ .name = "access-control-request-method", .value = "POST" },
    }));
}

test "gRPC-Web CORS response headers own request and policy values" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownedHeaders, .{});
    const any: cors.Policy = .{ .allow_any_origin = true };
    var headers = try cors.Headers.init(std.testing.allocator, any, try cors.evaluate(any, "POST", &.{.{ .name = "origin", .value = "https://public.example" }}));
    defer headers.deinit();
    try std.testing.expectEqualStrings("*", value(headers.fields, "access-control-allow-origin").?);
    try std.testing.expect(value(headers.fields, "access-control-allow-credentials") == null);
}

fn ownedHeaders(allocator: std.mem.Allocator) !void {
    var origin = "https://app.example".*;
    const decision = try cors.evaluate(policy, "OPTIONS", &.{
        .{ .name = "origin", .value = &origin },
        .{ .name = "access-control-request-method", .value = "POST" },
    });
    var headers = try cors.Headers.init(allocator, policy, decision);
    defer headers.deinit();
    @memset(&origin, 'x');
    try std.testing.expectEqualStrings("https://app.example", value(headers.fields, "access-control-allow-origin").?);
    try std.testing.expectEqualStrings("true", value(headers.fields, "access-control-allow-credentials").?);
    try std.testing.expectEqualStrings("POST", value(headers.fields, "access-control-allow-methods").?);
    try std.testing.expectEqualStrings("600", value(headers.fields, "access-control-max-age").?);
}

fn value(fields: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (fields) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}
