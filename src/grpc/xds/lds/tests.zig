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
    // HTTP RBAC filter config: rules (field 1) wraps the RBAC policy.
    const rbac_value = "\x0a\x11\x08\x00\x12\x0d\x0a\x01p\x12\x08\x0a\x02\x18\x01\x12\x02\x18\x01";
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
    const rbac_value = "\x0a\x11\x08\x01\x12\x0d\x0a\x01p\x12\x08\x0a\x02\x18\x01\x12\x02\x22\x00";
    const bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "rbac", .type_name = lds.resource.rbac_type, .value = rbac_value },
        .{},
    } });
    defer gpa.free(bytes);
    try std.testing.expectError(error.UnsupportedRbacFeature, lds.decode(gpa, bytes, .{}));
}

fn encodeFault(allocator: std.mem.Allocator, abort: ?[]const u8, delay: ?[]const u8) ![]u8 {
    var fault = fixture.Builder{ .allocator = allocator };
    errdefer fault.deinit();
    if (abort) |value| try fault.bytes(2, value);
    if (delay) |value| try fault.bytes(1, value);
    return fault.data.toOwnedSlice(allocator);
}

fn headerAbort(allocator: std.mem.Allocator, numerator: u32) ![]u8 {
    var abort = fixture.Builder{ .allocator = allocator };
    defer abort.deinit();
    var marker = fixture.Builder{ .allocator = gpa };
    defer marker.deinit();
    try abort.bytes(4, marker.data.items);
    var percentage = fixture.Builder{ .allocator = gpa };
    defer percentage.deinit();
    try percentage.number(1, numerator);
    try percentage.number(2, 0);
    try abort.bytes(3, percentage.data.items);
    return abort.data.toOwnedSlice(allocator);
}

test "gRPC LDS accepts a fault filter and orders it after RBAC" {
    const fault_value = try headerAbort(gpa, 100);
    defer gpa.free(fault_value);
    const fault = try encodeFault(gpa, fault_value, null);
    defer gpa.free(fault);
    const bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = fault },
        .{},
    } });
    defer gpa.free(bytes);
    var owned = try lds.decode(gpa, bytes, .{});
    defer owned.deinit();
    try std.testing.expect(owned.value.hcm.fault_config != null);

    const rbac_value = "\x0a\x11\x08\x00\x12\x0d\x0a\x01p\x12\x08\x0a\x02\x18\x01\x12\x02\x18\x01";
    const ordered = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "rbac", .type_name = lds.resource.rbac_type, .value = rbac_value },
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = fault },
        .{},
    } });
    defer gpa.free(ordered);
    var owned_ordered = try lds.decode(gpa, ordered, .{});
    defer owned_ordered.deinit();
    try std.testing.expect(owned_ordered.value.hcm.rbac_config != null and owned_ordered.value.hcm.fault_config != null);

    const disabled = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = fault, .disabled = true },
        .{},
    } });
    defer gpa.free(disabled);
    var owned_disabled = try lds.decode(gpa, disabled, .{});
    defer owned_disabled.deinit();
    try std.testing.expect(owned_disabled.value.hcm.fault_config == null);
}

test "gRPC LDS accepts fault header matchers" {
    const fault_value = try headerAbort(gpa, 100);
    defer gpa.free(fault_value);
    var matcher = fixture.Builder{ .allocator = gpa };
    defer matcher.deinit();
    try matcher.bytes(1, "x-fault");
    try matcher.number(7, 1);
    var fault = fixture.Builder{ .allocator = gpa };
    defer fault.deinit();
    try fault.bytes(2, fault_value);
    try fault.bytes(4, matcher.data.items);
    const bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = fault.data.items },
        .{},
    } });
    defer gpa.free(bytes);
    var owned = try lds.decode(gpa, bytes, .{});
    defer owned.deinit();
    try std.testing.expect(owned.value.hcm.fault_config != null);
}

test "gRPC LDS rejects duplicate fault filters and fault-before-RBAC ordering" {
    const fault_value = try headerAbort(gpa, 100);
    defer gpa.free(fault_value);
    const fault = try encodeFault(gpa, fault_value, null);
    defer gpa.free(fault);
    const duplicate = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "fault-a", .type_name = lds.resource.fault_type, .value = fault },
        .{ .name = "fault-b", .type_name = lds.resource.fault_type, .value = fault },
        .{},
    } });
    defer gpa.free(duplicate);
    try std.testing.expectError(error.InvalidLdsResource, lds.decode(gpa, duplicate, .{}));

    const rbac_value = "\x0a\x11\x08\x00\x12\x0d\x0a\x01p\x12\x08\x0a\x02\x18\x01\x12\x02\x18\x01";
    const reversed = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = fault },
        .{ .name = "rbac", .type_name = lds.resource.rbac_type, .value = rbac_value },
        .{},
    } });
    defer gpa.free(reversed);
    try std.testing.expectError(error.UnsupportedLdsFeature, lds.decode(gpa, reversed, .{}));
}

test "gRPC LDS rejects malformed and unsupported fault filters" {
    var abort = fixture.Builder{ .allocator = gpa };
    defer abort.deinit();
    try abort.number(5, 14);
    const missing_percentage = try encodeFault(gpa, abort.data.items, null);
    defer gpa.free(missing_percentage);
    const bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = missing_percentage },
        .{},
    } });
    defer gpa.free(bytes);
    try std.testing.expectError(error.InvalidFaultResource, lds.decode(gpa, bytes, .{}));

    var unsupported = fixture.Builder{ .allocator = gpa };
    defer unsupported.deinit();
    try unsupported.bytes(5, "x");
    const unsupported_bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = unsupported.data.items },
        .{},
    } });
    defer gpa.free(unsupported_bytes);
    try std.testing.expectError(error.UnsupportedFaultFeature, lds.decode(gpa, unsupported_bytes, .{}));

    const invalid_percentage = try headerAbort(gpa, 100);
    defer gpa.free(invalid_percentage);
    var no_percentage = fixture.Builder{ .allocator = gpa };
    defer no_percentage.deinit();
    try no_percentage.bytes(4, "");
    const no_percentage_fault = try encodeFault(gpa, no_percentage.data.items, null);
    defer gpa.free(no_percentage_fault);
    const no_percentage_bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = no_percentage_fault },
        .{},
    } });
    defer gpa.free(no_percentage_bytes);
    try std.testing.expectError(error.InvalidFaultResource, lds.decode(gpa, no_percentage_bytes, .{}));
}

test "gRPC LDS accepts a header-mutation filter" {
    const config = try fixture.headerMutation(gpa);
    defer gpa.free(config);
    const bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "hm", .type_name = lds.resource.header_mutation_type, .value = config },
        .{},
    } });
    defer gpa.free(bytes);
    var owned = try lds.decode(gpa, bytes, .{});
    defer owned.deinit();
    try std.testing.expect(owned.value.hcm.header_mutation_config != null);
    try std.testing.expectEqualStrings("hm", owned.value.hcm.header_mutation_name.?);

    var bad_name = fixture.Builder{ .allocator = gpa };
    defer bad_name.deinit();
    try bad_name.bytes(1, "Bad Name");
    var bad_option = fixture.Builder{ .allocator = gpa };
    defer bad_option.deinit();
    try bad_option.bytes(1, bad_name.data.items);
    var bad_mutations = fixture.Builder{ .allocator = gpa };
    defer bad_mutations.deinit();
    try bad_mutations.bytes(1, bad_option.data.items);
    var bad_config = fixture.Builder{ .allocator = gpa };
    defer bad_config.deinit();
    try bad_config.bytes(1, bad_mutations.data.items);
    const bad_bytes = try fixture.encode(gpa, .{ .filters = &.{
        .{ .name = "hm", .type_name = lds.resource.header_mutation_type, .value = bad_config.data.items },
        .{},
    } });
    defer gpa.free(bad_bytes);
    try std.testing.expectError(error.InvalidLdsResource, lds.decode(gpa, bad_bytes, .{}));
}
