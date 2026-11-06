const std = @import("std");
const lds = @import("../lds.zig");
const rds = @import("../rds.zig");
const fixture = @import("testing.zig");
const route_fixture = @import("../rds/testing.zig");
const gpa = std.testing.allocator;
test "gRPC LDS owns API listener HCM dynamic route identity and timeout" {
    const bytes = try fixture.encode(gpa, .{ .route_name = "routes-a", .maximum_ms = 50 });
    var owned = try lds.decode(gpa, bytes, .{});
    gpa.free(bytes);
    defer owned.deinit();
    try std.testing.expectEqualStrings("frontend", owned.value.name);
    try std.testing.expectEqualStrings("routes-a", owned.value.hcm.route_source.rds);
    try std.testing.expectEqual(@as(i96, 50 * std.time.ns_per_ms), owned.value.hcm.max_stream_duration.?.nanoseconds);
    try std.testing.expect(owned.inline_rds == null);
    try std.testing.expectEqual(@as(usize, 1), owned.value.hcm.filters.len);
}
test "gRPC LDS validates inline RDS once and transfers parsed storage without losing ownership" {
    const routes = try route_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/" }}, null);
    defer gpa.free(routes);
    const bytes = try fixture.encode(gpa, .{ .inline_rds = routes, .maximum_ms = 0 });
    defer gpa.free(bytes);
    const Harness = struct {
        fn run(allocator: std.mem.Allocator, image: []const u8) !void {
            var owned = try lds.decode(allocator, image, .{});
            defer owned.deinit();
            try std.testing.expectEqualStrings("inline", owned.inline_rds.?.value.name);
            try std.testing.expectEqual(@as(i96, 0), owned.value.hcm.max_stream_duration.?.nanoseconds);
            var controller = try lds.Controller.init(allocator, .{ .listener_name = "frontend", .authority = "backend.test" });
            defer controller.deinit();
            const snapshot = try controller.takeInline(&owned);
            defer snapshot.release();
            try std.testing.expect(owned.inline_rds == null);
            try std.testing.expectEqualStrings("inline", snapshot.resource.value.name);
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{bytes});
}
test "gRPC LDS effective filter chain requires one terminal router and validates optional filters" {
    for ([_][]const fixture.Filter{
        &.{ .{ .name = "unknown", .type_name = "custom.Unknown", .optional = true }, .{} },
        &.{ .{}, .{ .name = "unknown", .type_name = "custom.Unknown", .optional = true } },
    }) |filters| {
        const bytes = try fixture.encode(gpa, .{ .filters = filters });
        defer gpa.free(bytes);
        var owned = try lds.decode(gpa, bytes, .{});
        defer owned.deinit();
    }
    for ([_][]const fixture.Filter{ &.{}, &.{ .{}, .{ .name = "router2" } }, &.{.{ .disabled = true }}, &.{.{ .name = "optional", .type_name = "custom.Unknown", .optional = true }} }) |filters| {
        const bytes = try fixture.encode(gpa, .{ .filters = filters });
        defer gpa.free(bytes);
        try std.testing.expectError(error.InvalidLdsResource, lds.decode(gpa, bytes, .{}));
    }
    const unknown = try fixture.encode(gpa, .{ .filters = &.{.{ .type_name = "custom.Required" }} });
    defer gpa.free(unknown);
    try std.testing.expectError(error.UnsupportedLdsFeature, lds.decode(gpa, unknown, .{}));
    const duplicate = try fixture.encode(gpa, .{ .filters = &.{ .{ .name = "same", .type_name = "custom.Unknown", .optional = true }, .{ .name = "same" } } });
    defer gpa.free(duplicate);
    try std.testing.expectError(error.InvalidLdsResource, lds.decode(gpa, duplicate, .{}));
    const malformed = try fixture.encode(gpa, .{ .filters = &.{.{ .value = "\x0a\x01\x08" }} });
    defer gpa.free(malformed);
    try std.testing.expectError(error.TruncatedMessage, lds.decode(gpa, malformed, .{}));
}
test "gRPC LDS rejects unsupported sources scoped routes forwarding state and bounded resources" {
    const bytes = try fixture.encode(gpa, .{});
    defer gpa.free(bytes);
    try std.testing.expectError(error.LdsLimitExceeded, lds.decode(gpa, bytes, .{ .max_bytes = 1 }));
    try std.testing.expectError(error.LdsLimitExceeded, lds.decode(gpa, bytes, .{ .max_http_filters = 0 }));
    try std.testing.expectError(error.LdsLimitExceeded, lds.decode(gpa, bytes, .{ .max_storage_bytes = 1 }));
    const bad_source = try fixture.encode(gpa, .{ .source = "\x12\x00" });
    defer gpa.free(bad_source);
    try std.testing.expectError(error.InvalidLdsResource, lds.decode(gpa, bad_source, .{}));
    for ([_][]const u8{ "\x98\x01\x01", "\xf2\x02\x00" }) |extra| {
        const encoded = try fixture.encode(gpa, .{ .hcm_extra = extra });
        defer gpa.free(encoded);
        try std.testing.expectError(error.InvalidLdsResource, lds.decode(gpa, encoded, .{}));
    }
    const scoped = try fixture.encode(gpa, .{ .hcm_extra = "\xfa\x01\x00" });
    defer gpa.free(scoped);
    try std.testing.expectError(error.UnsupportedLdsFeature, lds.decode(gpa, scoped, .{}));
    try std.testing.expectError(error.InvalidLdsResource, lds.decode(gpa, "", .{}));
    _ = rds;
}

test "gRPC LDS accepts an RBAC filter before the terminal router" {
    const rbac_value = "\x08\x01\x12\x0d\x0a\x01p\x12\x08\x0a\x02\x18\x01\x12\x02\x18\x01";
    const bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "rbac", .type_name = lds.resource.rbac_type, .value = rbac_value },
        .{},
    } });
    defer gpa.free(bytes);
    var owned = try lds.decode(gpa, bytes, .{});
    defer owned.deinit();
    try std.testing.expect(owned.value.hcm.rbac_config != null);
}

test "gRPC LDS rejects an unsupported RBAC principal" {
    const rbac_value = "\x08\x01\x12\x0d\x0a\x01p\x12\x08\x0a\x02\x18\x01\x12\x02\x22\x00";
    const bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "rbac", .type_name = lds.resource.rbac_type, .value = rbac_value },
        .{},
    } });
    defer gpa.free(bytes);
    try std.testing.expectError(error.UnsupportedRbacFeature, lds.decode(gpa, bytes, .{}));
}
