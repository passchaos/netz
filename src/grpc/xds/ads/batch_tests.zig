const std = @import("std");
const state = @import("subscriptions.zig");
const gpa = std.testing.allocator;
test "gRPC ADS batched subscriptions prepare capacity and names before one commit" {
    var subscriptions = state.State{ .allocator = gpa, .options = .{ .max_types = 3 } };
    defer subscriptions.deinit();
    try subscriptions.set("lds", &.{"listener"});
    var batch = try subscriptions.prepareMany(&.{ .{ .type_url = "cds", .names = &.{ "b", "a" } }, .{ .type_url = "eds", .names = &.{"service"} } });
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), subscriptions.entries.items.len);
    batch.commit();
    try std.testing.expectEqual(@as(usize, 3), subscriptions.entries.items.len);
    try std.testing.expectEqualStrings("a", subscriptions.find("cds").?.names[0]);
    try std.testing.expectEqualStrings("service", subscriptions.find("eds").?.names[0]);
    try std.testing.expectError(error.DiscoveryTypeLimit, subscriptions.prepareMany(&.{ .{ .type_url = "new1", .names = &.{} }, .{ .type_url = "new2", .names = &.{} } }));
    var aborted = try subscriptions.prepareMany(&.{ .{ .type_url = "cds", .names = &.{"discarded"} }, .{ .type_url = "eds", .names = &.{"discarded"} } });
    aborted.deinit();
    try std.testing.expectEqualStrings("a", subscriptions.find("cds").?.names[0]);
    try std.testing.expectEqualStrings("service", subscriptions.find("eds").?.names[0]);
}
test "gRPC ADS batched subscription allocation failure preserves previous desired state" {
    const Harness = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var subscriptions = state.State{ .allocator = allocator, .options = .{} };
            defer subscriptions.deinit();
            try subscriptions.set("lds", &.{"listener"});
            var batch = try subscriptions.prepareMany(&.{ .{ .type_url = "cds", .names = &.{"cluster"} }, .{ .type_url = "eds", .names = &.{"service"} } });
            defer batch.deinit();
            batch.commit();
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{});
}
