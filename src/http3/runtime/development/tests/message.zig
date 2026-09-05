const std = @import("std");
const message = @import("../message.zig");

test "HTTP/3 development request batch initialization is transactional" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        initAndDeinitBatch,
        .{},
    );
}

fn initAndDeinitBatch(allocator: std.mem.Allocator) !void {
    var batch = try message.OwnedRequestBatch.init(allocator, 4);
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 4), batch.requests.len);
    try std.testing.expectEqual(@as(usize, 4), batch.errors.len);
    try std.testing.expectEqual(@as(usize, 0), batch.receivedCount());
    try std.testing.expectEqual(@as(usize, 4), batch.successCount());
    try std.testing.expect(batch.firstError() == null);
}
