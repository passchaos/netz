const std = @import("std");
const orca = @import("../orca.zig");

const report: orca.LoadReport = .{
    .cpu_utilization = 0.5,
    .memory_utilization = 0.25,
    .rps = 7,
    .request_cost = &.{.{ .name = "cost", .value = 3 }},
    .utilization = &.{.{ .name = "util", .value = 0.75 }},
    .rps_fractional = 10,
    .eps = 2,
    .named_metrics = &.{.{ .name = "opaque", .value = -4 }},
    .application_utilization = 1.25,
};

test "gRPC ORCA per-RPC report matches protobuf wire and round trips" {
    const encoded = try orca.encodeAlloc(std.testing.allocator, report);
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualSlices(
        u8,
        "\x09\x00\x00\x00\x00\x00\x00\xe0\x3f" ++
            "\x11\x00\x00\x00\x00\x00\x00\xd0\x3f" ++
            "\x18\x07" ++
            "\x22\x0f\x0a\x04cost\x11\x00\x00\x00\x00\x00\x00\x08\x40" ++
            "\x2a\x0f\x0a\x04util\x11\x00\x00\x00\x00\x00\x00\xe8\x3f" ++
            "\x31\x00\x00\x00\x00\x00\x00\x24\x40" ++
            "\x39\x00\x00\x00\x00\x00\x00\x00\x40" ++
            "\x42\x11\x0a\x06opaque\x11\x00\x00\x00\x00\x00\x00\x10\xc0" ++
            "\x49\x00\x00\x00\x00\x00\x00\xf4\x3f",
        encoded,
    );
    var decoded = try orca.decodeAlloc(std.testing.allocator, encoded);
    defer decoded.deinit();
    try expectReport(decoded.report, report);
    var copy = try decoded.clone(std.testing.allocator);
    defer copy.deinit();
    try expectReport(copy.report, report);
}

test "gRPC ORCA follows protobuf last value and unknown field semantics" {
    const encoded =
        "\x09\x00\x00\x00\x00\x00\x00\xf0\x3f" ++
        "\x09\x00\x00\x00\x00\x00\x00\xe0\x3f" ++
        "\x22\x0f\x0a\x04cost\x11\x00\x00\x00\x00\x00\x00\x00\x40" ++
        "\x22\x0f\x0a\x04cost\x11\x00\x00\x00\x00\x00\x00\x08\x40" ++
        "\x50\x01";
    var decoded = try orca.decodeAlloc(std.testing.allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(f64, 0.5), decoded.report.cpu_utilization);
    try std.testing.expectEqual(@as(usize, 1), decoded.report.request_cost.len);
    try std.testing.expectEqual(@as(f64, 3), decoded.report.request_cost[0].value);
}

test "gRPC ORCA metadata decodes once and rejects ambiguous reports" {
    const encoded = try orca.encodeAlloc(std.testing.allocator, report);
    defer std.testing.allocator.free(encoded);
    const base64 = try std.testing.allocator.alloc(
        u8,
        std.base64.standard.Encoder.calcSize(encoded.len),
    );
    defer std.testing.allocator.free(base64);
    _ = std.base64.standard.Encoder.encode(base64, encoded);
    var decoded = (try orca.fromMetadataAlloc(
        std.testing.allocator,
        &.{},
        &.{.{ .name = orca.name, .value = base64 }},
    )).?;
    defer decoded.deinit();
    try expectReport(decoded.report, report);
    try std.testing.expect(try orca.fromMetadataAlloc(
        std.testing.allocator,
        &.{},
        &.{},
    ) == null);
    try std.testing.expectError(
        error.DuplicateLoadReport,
        orca.fromMetadataAlloc(
            std.testing.allocator,
            &.{.{ .name = orca.name, .value = base64 }},
            &.{.{ .name = orca.name, .value = base64 }},
        ),
    );
    const joined = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s},{s}",
        .{ base64, base64 },
    );
    defer std.testing.allocator.free(joined);
    try std.testing.expectError(
        error.DuplicateLoadReport,
        orca.fromMetadataAlloc(
            std.testing.allocator,
            &.{},
            &.{.{ .name = orca.name, .value = joined }},
        ),
    );
    try std.testing.expectError(
        error.InvalidLoadReport,
        orca.fromMetadataAlloc(
            std.testing.allocator,
            &.{.{ .name = orca.name, .value = base64 }},
            &.{.{ .name = "grpc-status", .value = "0" }},
        ),
    );
}

test "gRPC ORCA validates bounds malformed protobuf and allocations" {
    try std.testing.expectError(
        error.InvalidLoadReport,
        orca.validate(.{ .memory_utilization = 1.1 }),
    );
    try std.testing.expectError(
        error.InvalidLoadReport,
        orca.validate(.{ .cpu_utilization = std.math.nan(f64) }),
    );
    try std.testing.expectError(
        error.InvalidLoadReport,
        orca.validate(.{ .utilization = &.{.{ .name = "util", .value = -0.1 }} }),
    );
    try std.testing.expectError(
        error.InvalidLoadReport,
        orca.validate(.{ .request_cost = &.{
            .{ .name = "same", .value = 1 },
            .{ .name = "same", .value = 2 },
        } }),
    );
    try std.testing.expectError(
        error.TruncatedMessage,
        orca.decodeAlloc(std.testing.allocator, "\x09\x00"),
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationCase,
        .{},
    );
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const encoded = try orca.encodeAlloc(allocator, report);
    defer allocator.free(encoded);
    var decoded = try orca.decodeAlloc(allocator, encoded);
    defer decoded.deinit();
    try expectReport(decoded.report, report);
    const base64 = try allocator.alloc(
        u8,
        std.base64.standard_no_pad.Encoder.calcSize(encoded.len),
    );
    defer allocator.free(base64);
    _ = std.base64.standard_no_pad.Encoder.encode(base64, encoded);
    var metadata_report = (try orca.fromMetadataAlloc(
        allocator,
        &.{},
        &.{.{ .name = orca.name, .value = base64 }},
    )).?;
    defer metadata_report.deinit();
    try expectReport(metadata_report.report, report);
}

fn expectReport(actual: orca.LoadReport, expected: orca.LoadReport) !void {
    try std.testing.expectEqual(expected.cpu_utilization, actual.cpu_utilization);
    try std.testing.expectEqual(expected.memory_utilization, actual.memory_utilization);
    try std.testing.expectEqual(expected.rps, actual.rps);
    try std.testing.expectEqual(expected.rps_fractional, actual.rps_fractional);
    try std.testing.expectEqual(expected.eps, actual.eps);
    try std.testing.expectEqual(expected.application_utilization, actual.application_utilization);
    try expectMetrics(actual.request_cost, expected.request_cost);
    try expectMetrics(actual.utilization, expected.utilization);
    try expectMetrics(actual.named_metrics, expected.named_metrics);
}

fn expectMetrics(actual: []const orca.Metric, expected: []const orca.Metric) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (actual, expected) |found, wanted| {
        try std.testing.expectEqualStrings(wanted.name, found.name);
        try std.testing.expectEqual(wanted.value, found.value);
    }
}
