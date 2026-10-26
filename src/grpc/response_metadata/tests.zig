const std = @import("std");
const policy = @import("../response_metadata.zig");
const http2 = @import("../../http2/mod.zig");

test "gRPC response metadata prefers explicit status over HTTP and media type" {
    var terminal = try policy.parseTerminal(std.testing.allocator, 503, &.{
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "grpc-status", .value = "16" },
        .{ .name = "grpc-message", .value = "denied%20%C3%A9%ZZ" },
    }, &.{});
    defer terminal.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 16), @intFromEnum(terminal.status));
    try std.testing.expectEqualStrings("denied é%ZZ", terminal.status_message);
    try std.testing.expect(!policy.parseBody(503, &.{.{ .name = "content-type", .value = "text/plain" }}, &.{}));
    var trailing = try policy.parseTerminal(std.testing.allocator, 200, &.{.{ .name = "grpc-status", .value = "0" }}, &.{.{ .name = "grpc-status", .value = "7" }});
    defer trailing.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 7), @intFromEnum(trailing.status));
}

test "gRPC response metadata synthesizes missing malformed and ambiguous status" {
    const allocator = std.testing.allocator;
    var missing = try policy.parseTerminal(allocator, 200, &.{}, &.{});
    defer missing.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(missing.status));
    try std.testing.expectEqualStrings("HTTP status 200 without grpc-status", missing.status_message);
    for ([_][]const u8{ "", "99", "07", "+7", "0,7" }) |raw| {
        var terminal = try policy.parseTerminal(allocator, 503, &.{.{ .name = "grpc-status", .value = raw }}, &.{});
        defer terminal.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 2), @intFromEnum(terminal.status));
        try std.testing.expectEqualStrings("Invalid grpc-status in response", terminal.status_message);
    }
    var duplicate = try policy.parseTerminal(allocator, 200, &.{}, &.{ .{ .name = "grpc-status", .value = "0" }, .{ .name = "grpc-status", .value = "7" } });
    defer duplicate.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(duplicate.status));
}

test "gRPC response metadata keeps details validation and allocation ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var terminal = try policy.parseTerminal(allocator, 503, &.{
        .{ .name = "grpc-status", .value = "7" },                 .{ .name = "grpc-status-details-bin", .value = "CAc" },
        .{ .name = "grpc-message", .value = "denied%20request" },
    }, &.{});
    defer terminal.deinit(allocator);
    try std.testing.expectEqualSlices(u8, "\x08\x07", terminal.status_details.?.bytes);
    var rejected = policy.parseTerminal(allocator, 200, &.{
        .{ .name = "grpc-status", .value = "16" }, .{ .name = "grpc-status-details-bin", .value = "CAc" },
    }, &.{}) catch |err| {
        if (err == error.OutOfMemory) return err;
        try std.testing.expectEqual(error.StatusDetailsMismatch, err);
        return;
    };
    defer rejected.deinit(allocator);
    return error.TestExpectedError;
}

test {
    _ = @import("runtime_tests.zig");
}
