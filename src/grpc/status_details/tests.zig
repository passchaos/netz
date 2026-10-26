const std = @import("std");
const details = @import("../status_details.zig");
const grpc = @import("../mod.zig");
const h2 = @import("../../http2/mod.zig");

const golden = "\x08\x07\x12\x06denied\x1a\x08\x0a\x03url\x12\x01\xff";

test "gRPC status details preserves protobuf envelope and opaque Any payloads" {
    const allocator = std.testing.allocator;
    const bytes = try details.encodeAlloc(allocator, .permission_denied, "denied", &.{.{ .type_url = "url", .value = "\xff" }});
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, golden, bytes);
    const view = try details.validate(.permission_denied, bytes);
    try std.testing.expectEqual(grpc.Status.permission_denied, view.code.?);
    try std.testing.expectEqualStrings("denied", view.message);
    var iterator = view.details();
    const any = (try iterator.next()).?;
    try std.testing.expectEqualStrings("url", any.type_url);
    try std.testing.expectEqualSlices(u8, "\xff", any.value);
    try std.testing.expect(try iterator.next() == null);
    try std.testing.expectError(error.StatusDetailsMismatch, details.validate(.unauthenticated, bytes));
    try std.testing.expectError(error.InvalidStatusDetails, details.validate(.ok, bytes));
}

test "gRPC status details accepts unknown fields groups and singular last value" {
    const view = try details.validate(.permission_denied, "\x08\x00\x12\x03old\x08\x07\x12\x03new" ++
        "\x20\x80\x01\x29abcdefgh\x32\x02??\x3b\x40\x01\x3c\x45abcd" ++
        "\x1a\x0a\x0a\x01a\x0a\x01b\x12\x00\x20\x01");
    try std.testing.expectEqualStrings("new", view.message);
    var iterator = view.details();
    try std.testing.expectEqualStrings("b", (try iterator.next()).?.type_url);
    try std.testing.expect(try iterator.next() == null);
    try std.testing.expect((try details.validate(.permission_denied, "\x12\x00")).code == null);
    try std.testing.expectError(error.StatusDetailsMismatch, details.validate(.permission_denied, "\x08\x07\x08\x00"));
    // A recognized number with a different legal wire type is unknown data.
    try std.testing.expect((try details.parse("\x0a\x01?\x10\x01")).code == null);
}

test "gRPC status details rejects malformed protobuf and invalid UTF8" {
    for ([_][]const u8{
        "\x00",                                         "\x08",         "\x08\x80",  "\x08\x11",     "\x08\xff\xff\xff\xff\x0f",
        "\x08\x80\x80\x80\x80\x80\x80\x80\x80\x80\x02", "\x12\x01\xff", "\x12\x02x", "\x1a\x01\x08", "\x1a\x03\x0a\x01\xff",
        "\x1a\x03\x12\x02x",                            "\x21abc",      "\x2dab",    "\x33\x3c",     "\x33",
        "\x34",                                         "\x26",
    }) |bytes| try std.testing.expectError(error.InvalidStatusDetails, details.parse(bytes));
    var nested: [202]u8 = undefined;
    @memset(nested[0..101], 0x23);
    @memset(nested[101..], 0x24);
    try std.testing.expectError(error.InvalidStatusDetails, details.parse(&nested));
}

test "gRPC status details metadata supports padded Base64 and rejects ambiguity" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "CAc", "CAc=" }) |raw| {
        var owned = (try details.fromMetadataAlloc(allocator, .permission_denied, &.{}, &.{
            .{ .name = "grpc-status", .value = "7" }, .{ .name = details.name, .value = raw },
        })).?;
        defer owned.deinit();
        try std.testing.expectEqualSlices(u8, "\x08\x07", owned.bytes);
    }
    try std.testing.expect(try details.fromMetadataAlloc(allocator, .ok, &.{}, &.{}) == null);
    try std.testing.expectError(error.InvalidStatusDetails, details.fromMetadataAlloc(allocator, .permission_denied, &.{}, &.{.{ .name = details.name, .value = "CAc" }}));
    try std.testing.expectError(error.InvalidStatusDetails, details.fromMetadataAlloc(allocator, .permission_denied, &.{}, &.{ .{ .name = "grpc-status", .value = "07" }, .{ .name = details.name, .value = "CAc" } }));
    for ([_][]const h2.Hpack.HeaderField{
        &.{ .{ .name = "grpc-status", .value = "7" }, .{ .name = details.name, .value = "CAc,CAc" } },
        &.{ .{ .name = details.name, .value = "CAc" }, .{ .name = details.name, .value = "CAc" } },
    }) |fields| try std.testing.expectError(error.InvalidStatusDetails, details.fromMetadataAlloc(allocator, .permission_denied, &.{}, fields));
    try std.testing.expectError(error.InvalidBinaryMetadata, details.fromMetadataAlloc(allocator, .permission_denied, &.{}, &.{ .{ .name = "grpc-status", .value = "7" }, .{ .name = details.name, .value = "@" } }));
    try std.testing.expectError(error.InvalidStatusDetails, details.fromMetadataAlloc(allocator, .permission_denied, &.{.{ .name = details.name, .value = "CAc" }}, &.{.{ .name = "grpc-status", .value = "7" }}));
}

test "gRPC status details envelope metadata clone and terminal allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const bytes = try details.encodeAlloc(allocator, .permission_denied, "denied", &.{.{ .type_url = "url", .value = "\xff" }});
    defer allocator.free(bytes);
    const encoded = try details.encodedAlloc(allocator, .permission_denied, bytes);
    defer allocator.free(encoded);
    var owned = (try details.fromMetadataAlloc(allocator, .permission_denied, &.{}, &.{ .{ .name = "grpc-status", .value = "7" }, .{ .name = details.name, .value = encoded } })).?;
    defer owned.deinit();
    var terminal = try grpc.stream.runtime.parseResponseTerminal(allocator, 200, &.{}, &.{ .{ .name = "grpc-status", .value = "7" }, .{ .name = "grpc-message", .value = "denied" }, .{ .name = details.name, .value = encoded } }, null);
    defer allocator.free(terminal.status_message);
    defer if (terminal.status_details) |*value| value.deinit();
    var copy = try owned.clone(allocator);
    defer copy.deinit();
    try std.testing.expectEqualSlices(u8, golden, copy.bytes);
    const block = try grpc.web.buildTrailerBlock(allocator, .{ .status = .permission_denied, .status_details = bytes });
    defer allocator.free(block);
    try std.testing.expect(std.mem.indexOf(u8, block, "grpc-status-details-bin:") != null);
}

test "gRPC status details rejects inconsistent server options before I/O" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var connection: h2.runtime.Connection = .{ .allocator = failing.allocator(), .io = undefined, .stream = undefined, .role = .server };
    try std.testing.expectError(error.StatusDetailsMismatch, grpc.writeUnaryResponse(&connection, failing.allocator(), 1, .{ .status = .unavailable, .status_details = golden, .trailers_only = true }));
    try std.testing.expectError(error.InvalidStatusDetails, grpc.web.buildTrailerBlock(failing.allocator(), .{ .status = .ok, .status_details = golden }));
    try std.testing.expect(!failing.has_induced_failure);
}
