const std = @import("std");
const oob = @import("oob.zig");

test "gRPC ORCA OOB request codec preserves interval and cost names" {
    const encoded = try oob.encodeRequestAlloc(std.testing.allocator, .{
        .report_interval = .fromNanoseconds(1_250_000_000),
        .request_cost_names = &.{ "query", "storage" },
    });
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualSlices(
        u8,
        "\x0a\x07\x08\x01\x10\x80\xe5\x9a\x77" ++
            "\x12\x05query\x12\x07storage",
        encoded,
    );
    var decoded = try oob.decodeRequestAlloc(std.testing.allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(
        @as(i96, 1_250_000_000),
        decoded.request.report_interval.nanoseconds,
    );
    try std.testing.expectEqual(@as(usize, 2), decoded.request.request_cost_names.len);
    try std.testing.expectEqualStrings("query", decoded.request.request_cost_names[0]);
    try std.testing.expectEqualStrings("storage", decoded.request.request_cost_names[1]);
}

test "gRPC ORCA OOB request follows protobuf last duration semantics" {
    var decoded = try oob.decodeRequestAlloc(
        std.testing.allocator,
        "\x0a\x02\x08\x02\x0a\x02\x08\x01" ++
            "\x18\x01",
    );
    defer decoded.deinit();
    try std.testing.expectEqual(
        @as(i96, 1_000_000_000),
        decoded.request.report_interval.nanoseconds,
    );
    try std.testing.expectEqual(@as(usize, 0), decoded.request.request_cost_names.len);
}

test "gRPC ORCA OOB request rejects invalid duration and UTF8" {
    try std.testing.expectError(
        error.InvalidReportInterval,
        oob.encodeRequestAlloc(std.testing.allocator, .{
            .report_interval = .fromNanoseconds(-1),
        }),
    );
    try std.testing.expectError(
        error.InvalidReportInterval,
        oob.decodeRequestAlloc(
            std.testing.allocator,
            "\x0a\x06\x10\x80\x94\xeb\xdc\x03",
        ),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        oob.decodeRequestAlloc(std.testing.allocator, "\x12\x01\xff"),
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationCase,
        .{},
    );
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const encoded = try oob.encodeRequestAlloc(allocator, .{
        .report_interval = .fromSeconds(1),
        .request_cost_names = &.{"cost"},
    });
    defer allocator.free(encoded);
    var decoded = try oob.decodeRequestAlloc(allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqualStrings(
        "cost",
        decoded.request.request_cost_names[0],
    );
}
